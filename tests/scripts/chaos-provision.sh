#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# chaos-provision.sh - provision the FULL Sentinel fail-closed stack in KinD
# for the Distributed Chaos Resilience Gate (used by chaos-gate.yml AND the
# Makefile chaos-* targets - keep both callers in sync).
#
# MODE:
#   stack (default): TLS secrets, runtime secrets, realm ConfigMap, all four
#       deployments (redis/postgres/keycloak 26.6.4 TLS/sentinel-api), EF
#       migrations for both contexts, API readiness wait.
#   mint:  Keycloak sentinel-gate client (PS256 + audience mapper) + gate-user
#       provisioning, then a DPoP-bound token pool (RFC 9449 cnf.jkt verified,
#       fail-close on unbounded tokens).
#   all:   stack then mint.
#
# ENV:
#   SENTINEL_API_IMAGE   local image tag to inject (default sentinel-api:chaos)
#   KEYCLOAK_URL         port-forward target (default https://localhost:8443)
#   KEYCLOAK_GATE_PASSWORD  must match the keycloak deployment env (default gate-pass)
#   MINT_COUNT           pool size (default 120)
#   EF_STARTUP           dotnet ef startup project (default samples/Sentinel.Sample.MinimalApi)
#
# Requires: kubectl, openssl, node, python3 (mint mode), dotnet (stack mode).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

MODE="${MODE:-stack}"
SENTINEL_API_IMAGE="${SENTINEL_API_IMAGE:-sentinel-api:chaos}"
KEYCLOAK_URL="${KEYCLOAK_URL:-https://localhost:8443}"
KEYCLOAK_GATE_PASSWORD="${KEYCLOAK_GATE_PASSWORD:-gate-pass}"
MINT_COUNT="${MINT_COUNT:-120}"
EF_STARTUP="${EF_STARTUP:-samples/Sentinel.Sample.MinimalApi}"
NS=sentinel-prod
POOL_OUT="${POOL_OUT:-tests/load/chaos-dpop-pool.json}"

WORK="$(mktemp -d)"
FORWARD_PIDS=()
cleanup() {
  for pid in "${FORWARD_PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

start_forward() { # start_forward <namespace> <svc> <port>
  kubectl port-forward -n "$1" "svc/$2" "$3:$3" >/dev/null 2>&1 &
  FORWARD_PIDS+=("$!")
  sleep 2
}

provision_stack() {
  echo "==> [1/6] TLS secrets from infra/certs (repo CA)"
  kubectl create secret tls sentinel-keycloak-tls -n keycloak \
    --cert=infra/certs/keycloak.crt --key=infra/certs/keycloak.key \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl create secret generic sentinel-ca-bundle -n "$NS" \
    --from-file=ca.crt=infra/certs/ca.crt \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  # API serving cert signed by the repo CA (SAN covers the in-cluster DNS names).
  openssl req -new -newkey ec:<(openssl ecparam -name secp384r1) -nodes \
    -keyout "$WORK/api.key" -out "$WORK/api.csr" \
    -subj "/CN=sentinel-api/O=Sentinel Security/C=GE" >/dev/null 2>&1
  cat > "$WORK/api.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = sentinel-api
DNS.2 = sentinel-api.sentinel-prod.svc
DNS.3 = sentinel-api.sentinel-prod.svc.cluster.local
DNS.4 = localhost
IP.1 = 127.0.0.1
EOF
  openssl x509 -req -in "$WORK/api.csr" -CA infra/certs/ca.crt -CAkey infra/certs/ca.key \
    -CAcreateserial -out "$WORK/api.crt" -days 30 -extfile "$WORK/api.ext" -sha256 >/dev/null 2>&1
  kubectl create secret tls sentinel-api-tls -n "$NS" \
    --cert="$WORK/api.crt" --key="$WORK/api.key" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  echo "==> [2/6] sentinel-runtime-secrets (match infra/k8s deployment env)"
  kubectl create secret generic sentinel-runtime-secrets -n "$NS" \
    --from-literal=postgres-connection-string="Host=postgres;Port=5432;Database=sentinel_dev;Username=postgres;Password=postgres" \
    --from-literal=redis-connection-string="redis:6379" \
    --from-literal=keycloak-client-secret="gate-client-secret" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  echo "==> [3/6] sentinel-realm-config ConfigMap (--import-realm baseline)"
  kubectl create configmap sentinel-realm-config -n keycloak \
    --from-file=sentinel.json=infra/keycloak/realms/sentinel.json \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  echo "==> [4/6] redis / postgres / keycloak / sentinel-api deployments"
  kubectl apply -f infra/k8s/redis-deployment.yaml
  kubectl apply -f infra/k8s/postgres-deployment.yaml
  kubectl apply -f infra/k8s/keycloak-deployment.yaml
  kubectl -n "$NS" wait --for=condition=available deployment/redis --timeout=180s
  kubectl -n "$NS" wait --for=condition=available deployment/postgres --timeout=180s
  kubectl -n keycloak wait --for=condition=available deployment/keycloak --timeout=300s

  sed "s|image: ghcr.io/acme/sentinel-api:v1.0.0|image: $SENTINEL_API_IMAGE|" \
    infra/k8s/sentinel-api-deployment.yaml | kubectl apply -f -
  # The gate migrates the schema itself (step 5); the external migrations
  # image (ghcr.io/acme/sentinel-migrations) is not provisionable from this
  # repository, so the initContainers are removed for the gate.
  kubectl patch deployment sentinel-api -n "$NS" --type json \
    -p '[{"op":"remove","path":"/spec/template/spec/initContainers"}]' >/dev/null

  echo "==> [5/6] EF migrations (security + domain contexts)"
  start_forward "$NS" postgres 5432
  CONN="Host=localhost;Port=5432;Database=sentinel_dev;Username=postgres;Password=postgres"
  [ -f .config/dotnet-tools.json ] && dotnet tool restore >/dev/null
  dotnet ef database update --project src/Sentinel.EntityFrameworkCore \
    --startup-project "$EF_STARTUP" --connection "$CONN"
  dotnet ef database update --project src/Sentinel.Infrastructure \
    --startup-project "$EF_STARTUP" --connection "$CONN"

  echo "==> [6/6] wait for sentinel-api readiness"
  kubectl -n "$NS" wait --for=condition=available deployment/sentinel-api --timeout=180s
  echo "OK: chaos stack provisioned (image=$SENTINEL_API_IMAGE)"
}

provision_keycloak_gate() {
  echo "==> provisioning sentinel-gate client + gate-user via Keycloak admin API"
  start_forward keycloak keycloak 8443

  ADMIN_TOKEN=$(curl -ksf -X POST \
    "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "grant_type=password&client_id=admin-cli&username=admin&password=admin" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

  GATE_CLIENT_ID=$(curl -ksf "$KEYCLOAK_URL/admin/realms/sentinel/clients?clientId=sentinel-gate" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if d else "")')

  # sentinel-gate: PS256, direct access grants, DPoP-bound tokens, and an
  # audience mapper so the JWT's aud contains sentinel-api (Sentinel enforces
  # Keycloak__Audience - a token without it is rejected with invalid_token).
  CLIENT_JSON='{"clientId":"sentinel-gate","enabled":true,"publicClient":true,"standardFlowEnabled":false,"directAccessGrantsEnabled":true,"attributes":{"access.token.signed.response.alg":"PS256","access.token.lifespan":"300","dpop.bound.access.tokens":"true"},"protocolMappers":[{"name":"sentinel-api-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.client.audience":"sentinel-api","access.token.claim":"true","id.token.claim":"false","access.tokenResponse.claim":"false"}}]}'
  if [ -z "$GATE_CLIENT_ID" ]; then
    GATE_CLIENT_ID=$(curl -ksf -X POST "$KEYCLOAK_URL/admin/realms/sentinel/clients" \
      -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
      -d "$CLIENT_JSON" -o /dev/null -w '%{redirect_url}' | sed 's#.*/##')
    echo "created sentinel-gate client (id=$GATE_CLIENT_ID)"
  else
    MAPPER_NAME=$(curl -ksf "$KEYCLOAK_URL/admin/realms/sentinel/clients/$GATE_CLIENT_ID/protocol-mappers/models" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      | python3 -c 'import json,sys; print(next((m["name"] for m in json.load(sys.stdin) if m["name"]=="sentinel-api-audience"), ""))')
    if [ -z "$MAPPER_NAME" ]; then
      curl -ksf -X POST "$KEYCLOAK_URL/admin/realms/sentinel/clients/$GATE_CLIENT_ID/protocol-mappers/models" \
        -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
        -d '{"name":"sentinel-api-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.client.audience":"sentinel-api","access.token.claim":"true","id.token.claim":"false","access.tokenResponse.claim":"false"}}' \
        >/dev/null
      echo "added sentinel-api-audience mapper to existing client"
    fi
  fi

  GATE_USER_ID=$(curl -ksf "$KEYCLOAK_URL/admin/realms/sentinel/users?username=gate-user" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if d else "")')
  if [ -z "$GATE_USER_ID" ]; then
    curl -ksf -X POST "$KEYCLOAK_URL/admin/realms/sentinel/users" \
      -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
      -d "{\"username\":\"gate-user\",\"enabled\":true,\"emailVerified\":true,\"credentials\":[{\"type\":\"password\",\"value\":\"$KEYCLOAK_GATE_PASSWORD\",\"temporary\":false}]}" \
      >/dev/null
    echo "created gate-user"
  fi
}

mint_pool() {
  provision_keycloak_gate
  echo "==> minting DPoP-bound token pool (cnf.jkt, fail-close on unbounded)"
  NODE_TLS_REJECT_UNAUTHORIZED=0 node tests/scripts/mint-dpop-pool.mjs \
    --count "$MINT_COUNT" \
    --out "$POOL_OUT" \
    --keycloak-url "$KEYCLOAK_URL" \
    --realm sentinel --client sentinel-gate \
    --username gate-user --password "$KEYCLOAK_GATE_PASSWORD"
  echo "OK: DPoP-bound pool written to $POOL_OUT"
}

case "$MODE" in
  stack) provision_stack ;;
  mint) mint_pool ;;
  all)
    provision_stack
    mint_pool
    ;;
  *)
    echo "unknown MODE=$MODE (stack|mint|all)" >&2
    exit 2
    ;;
esac