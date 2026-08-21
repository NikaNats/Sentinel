#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# validate-observability.sh - Layer-2 Observability E2E Gate.
#
# Boots the full FAPI 2.0 stack with the observability overlay (collector +
# Prometheus + Loki + Tempo), provisions the DPoP-bound gate client/user in
# Keycloak, mints a real token pool, then emits REAL security events and FAILS
# CLOSED unless every observability contract holds:
#   1. Prometheus scrapes auth_dpop_failures_total / auth_jti_replays_total and
#      BOTH alerts (HighDPoPFailures, TokenReplayDetected) transition to firing.
#   2. Loki contains the PII-safe TOKEN_REPLAY_ALERT with the caller's
#      correlation id and 64-hex privacy hashes (no raw jti/sub/IP).
#   3. Tempo returns the request trace for service.name=sentinel-api.
#
# ENV:
#   API_URL                 (default http://localhost:5260)
#   PROMETHEUS_URL          (default http://localhost:9090)
#   LOKI_URL                (default http://localhost:3100)
#   TEMPO_URL               (default http://localhost:3200)
#   KEYCLOAK_URL            (default https://localhost:8443)
#   KEYCLOAK_GATE_PASSWORD  gate-user password (default gate-pass)
#
# Requires: docker, curl, node (24+), sed/awk, openssl-free (certs via repo).
# Used by the observability-gate job in .github/workflows/security-pipeline.yml.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

API_URL="${API_URL:-http://localhost:5260}"
PROMETHEUS_URL="${PROMETHEUS_URL:-http://localhost:9090}"
LOKI_URL="${LOKI_URL:-http://localhost:3100}"
TEMPO_URL="${TEMPO_URL:-http://localhost:3200}"
KEYCLOAK_URL="${KEYCLOAK_URL:-https://localhost:8443}"
KEYCLOAK_GATE_PASSWORD="${KEYCLOAK_GATE_PASSWORD:-gate-pass}"

COMPOSE_CMD=(docker compose -f docker-compose.yml -f infra/observability/docker-compose.observability.yml)

WORK="$(mktemp -d)"
POOL="$WORK/pool.json"
CORRELATION_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)"

cleanup() {
  "${COMPOSE_CMD[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }
ok() { echo "OK: $1"; }

json_field() { node -p "JSON.parse(require('fs').readFileSync(0,'utf8')).$1"; }

echo "==> [1/6] starting full stack with observability overlay"
"${COMPOSE_CMD[@]}" up -d --build >/dev/null

for i in $(seq 1 60); do
  curl -sf "$API_URL/healthz" >/dev/null 2>&1 && break
  [ "$i" -eq 60 ] && { echo "CRITICAL: sentinel-api failed to start"; "${COMPOSE_CMD[@]}" logs --tail=60 sentinel-api; exit 1; }
  sleep 3
done
ok "sentinel-api reachable at $API_URL/healthz"

for i in $(seq 1 40); do
  curl -ksf "$KEYCLOAK_URL/realms/sentinel/.well-known/openid-configuration" >/dev/null 2>&1 && break
  [ "$i" -eq 40 ] && { echo "CRITICAL: keycloak failed to start"; "${COMPOSE_CMD[@]}" logs --tail=60 keycloak; exit 1; }
  sleep 3
done
ok "keycloak reachable at $KEYCLOAK_URL"

for i in $(seq 1 40); do
  PROM_READY=false; LOKI_READY=false; TEMPO_READY=false
  curl -sf "$PROMETHEUS_URL/-/ready" >/dev/null 2>&1 && PROM_READY=true
  curl -sf "$LOKI_URL/ready" >/dev/null 2>&1 && LOKI_READY=true
  curl -sf "$TEMPO_URL/ready" >/dev/null 2>&1 && TEMPO_READY=true
  $PROM_READY && $LOKI_READY && $TEMPO_READY && break
  [ "$i" -eq 40 ] && { echo "CRITICAL: observability stack failed to start"; "${COMPOSE_CMD[@]}" logs --tail=60 collector prometheus loki tempo; exit 1; }
  sleep 3
done
ok "prometheus/loki/tempo ready"

echo "==> [2/6] provisioning sentinel-gate client + gate-user (Keycloak admin API)"
ADMIN_TOKEN="$(curl -ksf -X POST \
  "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password&client_id=admin-cli&username=admin&password=admin' \
  | json_field access_token)"

GATE_CLIENT_ID="$(curl -ksf "$KEYCLOAK_URL/admin/realms/sentinel/clients?clientId=sentinel-gate" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | node -p "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); d.length?d[0].id:''")"

# sentinel-gate: PS256, confidential client_credentials with ACR & Audience mappers
CLIENT_JSON='{"clientId":"sentinel-gate","name":"Sentinel Gate Client","enabled":true,"publicClient":false,"secret":"gate-client-secret","clientAuthenticatorType":"client-secret","serviceAccountsEnabled":true,"standardFlowEnabled":false,"directAccessGrantsEnabled":false,"attributes":{"access.token.signed.response.alg":"PS256","access.token.lifespan":"300","dpop.bound.access.tokens":"true"},"defaultClientScopes":["roles","profile","email"],"protocolMappers":[{"name":"sentinel-api-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.custom.audience":"sentinel-api","access.token.claim":"true","id.token.claim":"false"}},{"name":"acr-gate","protocol":"openid-connect","protocolMapper":"oidc-hardcoded-claim-mapper","config":{"claim.name":"acr","claim.value":"acr2","jsonType":"String","access.token.claim":"true","id.token.claim":"false"}}]}'
if [ -z "$GATE_CLIENT_ID" ]; then
  curl -ksf -X POST "$KEYCLOAK_URL/admin/realms/sentinel/clients" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    -d "$CLIENT_JSON" >/dev/null
  GATE_CLIENT_ID="$(curl -ksf "$KEYCLOAK_URL/admin/realms/sentinel/clients?clientId=sentinel-gate" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    | node -p "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); d.length?d[0].id:''")"
  ok "created sentinel-gate client (id=$GATE_CLIENT_ID)"
else
  ok "sentinel-gate client exists (id=$GATE_CLIENT_ID)"
fi

echo "==> [3/6] minting DPoP-bound token pool (fail-close on unbounded tokens)"
NODE_TLS_REJECT_UNAUTHORIZED=0 node tests/scripts/mint-dpop-pool.mjs \
  --count 2 --out "$POOL" \
  --keycloak-url "$KEYCLOAK_URL" \
  --realm sentinel --client sentinel-gate \
  --client-secret gate-client-secret
ok "pool written to $POOL"

echo "==> [4/6] emitting security events"
# Event A: burst of malformed DPoP proofs -> auth_dpop_failures_total
for _ in $(seq 1 10); do
  STATUS="$(curl -s -o /dev/null -w '%{http_code}' \
    -H 'Authorization: DPoP not.a.jwt' \
    -H 'DPoP: not.a.real.dpop.proof' \
    "$API_URL/v1/profile")"
  [ "$STATUS" = "401" ] || fail "malformed DPoP proof was not rejected (HTTP $STATUS)"
done
ok "10 malformed DPoP proofs rejected with 401"

# Event B: access-token jti replay. Request 1 consumes the nonce rotation;
# request 2 re-presents the SAME token with a FRESH proof -> TOKEN_REPLAY_ALERT.
TOKEN="$(node tests/scripts/sign-dpop-proof.mjs --pool "$POOL" --index 0 --print-token \
  --method GET --url "$API_URL/v1/profile")"
PROOF1="$(node tests/scripts/sign-dpop-proof.mjs --pool "$POOL" --index 0 \
  --method GET --url "$API_URL/v1/profile")"
RESP1="$(curl -s -D - -o /dev/null \
  -H "Authorization: DPoP $TOKEN" -H "DPoP: $PROOF1" -H "X-Correlation-ID: $CORRELATION_ID" \
  "$API_URL/v1/profile")"
STATUS1="$(printf '%s' "$RESP1" | head -n1 | awk '{print $2}')"
NONCE="$(printf '%s' "$RESP1" | grep -i '^DPoP-Nonce:' | tr -d '\r' | sed 's/^[^:]*: *//' || true)"

if [ "$STATUS1" != "200" ]; then
  echo "::error::First DPoP request failed with HTTP $STATUS1"
  echo "Response headers: $RESP1"
  "${COMPOSE_CMD[@]}" logs --tail=40 sentinel-api
  fail "first DPoP request failed (HTTP $STATUS1)"
fi

[ -n "$NONCE" ] || fail "no DPoP-Nonce returned on first request"
ok "first request accepted (200) with DPoP-Nonce rotation"

PROOF2="$(node tests/scripts/sign-dpop-proof.mjs --pool "$POOL" --index 0 \
  --method GET --url "$API_URL/v1/profile" --nonce "$NONCE")"
STATUS2="$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: DPoP $TOKEN" -H "DPoP: $PROOF2" -H "X-Correlation-ID: $CORRELATION_ID" \
  "$API_URL/v1/profile")"
[ "$STATUS2" = "401" ] || fail "replayed access token was NOT rejected (HTTP $STATUS2)"
ok "replayed access token rejected with 401 (auth_jti_replays_total + TOKEN_REPLAY_ALERT)"

echo "==> [5/6] asserting Prometheus alerts fire"
ALERTS_FIRING=false
for i in $(seq 1 20); do
  FIRING="$(curl -sf "$PROMETHEUS_URL/api/v1/alerts" 2>/dev/null \
    | node -p "
      const d=JSON.parse(require('fs').readFileSync(0,'utf8'));
      const names=new Set((d.data.alerts||[]).filter(a=>a.state==='firing').map(a=>a.labels.alertname));
      (names.has('HighDPoPFailures')&&names.has('TokenReplayDetected'))?'yes':'no';
    " || echo no)"
  [ "$FIRING" = "yes" ] && { ALERTS_FIRING=true; break; }
  sleep 5
done
[ "$ALERTS_FIRING" = "true" ] || fail "alerts HighDPoPFailures/TokenReplayDetected did not fire within 100s"
ok "Prometheus: HighDPoPFailures + TokenReplayDetected firing"

echo "==> [6/6] asserting Loki SIEM log + Tempo trace"
LOKI_FOUND=false
LOKI_JSON=""
for i in $(seq 1 15); do
  LOKI_JSON="$(curl -sf -G "$LOKI_URL/loki/api/v1/query_range" \
    --data-urlencode 'query={service_name="sentinel-api"} |= "TOKEN_REPLAY_ALERT"' \
    --data-urlencode 'limit=10' 2>/dev/null || true)"
  if printf '%s' "$LOKI_JSON" | grep -q 'TOKEN_REPLAY_ALERT'; then
    LOKI_FOUND=true
    break
  fi
  sleep 2
done

printf '%s' "$LOKI_JSON" | node -e "
  const d=JSON.parse(require('fs').readFileSync(0,'utf8'));
  const lines=[];
  for (const s of d.data.result||[]) for (const v of s.values||[]) lines.push(v[1]);
  if (!lines.length) { console.error('no TOKEN_REPLAY_ALERT lines in Loki'); process.exit(1); }
  const msg=lines[0];
  if (!msg.includes('TOKEN_REPLAY_ALERT')) { console.error('line missing marker'); process.exit(1); }
  if (!msg.includes('CorrelationId=$CORRELATION_ID')) { console.error('SIEM log lacks the caller correlation id'); process.exit(1); }
  if (msg.includes('127.0.0.1')) { console.error('raw client IP leaked into SIEM log'); process.exit(1); }
  const hashes=msg.match(/[0-9A-F]{64}/g)||[];
  if (hashes.length<2) { console.error('privacy hashes (64-hex) missing from SIEM log'); process.exit(1); }
  console.log('Loki: TOKEN_REPLAY_ALERT present with correlation id + 64-hex hashes, no raw PII');
"
ok "Loki SIEM alert verified (PII-safe)"

TEMPO_FOUND=false
TEMPO_JSON=""
for i in $(seq 1 15); do
  TEMPO_JSON="$(curl -sf -G "$TEMPO_URL/api/search" \
    --data-urlencode 'tags=service.name=sentinel-api' \
    --data-urlencode 'limit=10' 2>/dev/null || true)"
  if printf '%s' "$TEMPO_JSON" | grep -q 'traces'; then
    TEMPO_FOUND=true
    break
  fi
  sleep 2
done

printf '%s' "$TEMPO_JSON" | node -e "
  const d=JSON.parse(require('fs').readFileSync(0,'utf8'));
  const traces=(d.traces||[]).filter(t=>t.durationMs>0 && /^[0-9a-f]{32}\$/i.test(t.traceID||''));
  if (!traces.length) { console.error('no sentinel-api traces in Tempo'); process.exit(1); }
  console.log('Tempo: found '+traces.length+' trace(s) for sentinel-api');
"
ok "Tempo trace verified"

echo "PASS: Dual-Layer Observability Gate (Layer 2) - all contracts hold"