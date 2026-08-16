#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# run-fapi-conformance.sh - OIDF FAPI 2.0 Conformance Gate: evidence extraction & validation.
#
# Drives the official OpenID Foundation Conformance Suite REST API
# (https://www.certification.openid.net, hosted or self-hosted) end-to-end:
#   1. create a plan with the exact FAPI 2.0 Security Profile + DPoP variant
#      matrix (planName + variant are QUERY parameters; the configuration is
#      the JSON body - verified against the suite's own client implementations);
#   2. optionally provision the suite-generated client JWKS into Keycloak via
#      FAPI_PROVISION_HOOK (see provision-fapi-conformance-clients.sh);
#   3. start the plan, poll the plan-level aggregate result;
#   4. download and verify the evidence pack (exporthtml zip, result JSON,
#      certificate PDF) and write a SHA-256 chain-of-custody manifest.
#
# Two modes (FAPI_MODE):
#   local (default)   - suite runs locally via
#                       docker compose -f infra/fapi-conformance/docker-compose.yml;
#                       SUITE_URL defaults to https://localhost:8443 (nginx proxy),
#                       token defaults to local-dev-token; a pre-flight
#                       reachability check runs before plan creation.
#   remote            - hosted/self-hosted suite (certification runs):
#                       FAPI_SUITE_URL / FAPI_SUITE_TOKEN are REQUIRED.
#
# Required environment:
#   FAPI_SUITE_URL    conformance suite base URL (remote mode only)
#   FAPI_SUITE_TOKEN  API token for plan creation (remote mode only)
#   ISSUER_URL        Keycloak issuer under test, e.g.
#                     https://keycloak.staging.sentinel.io/realms/sentinel-dast
#                     LOCAL: https://host.docker.internal:8443/realms/sentinel-dast
#                     (the suite must be able to reach it)
#   RESOURCE_URL      public Sentinel API base URL used by DPoP resource tests
#   FAPI_CLIENT_ID    conformance client id (default: sentinel-fapi-conformance)
#   FAPI_CLIENT2_ID   second client id for mixup tests (default: sentinel-fapi-conformance-mixup)
#
# Optional:
#   FAPI_MODE         "local" (default) | "remote"
#   FAPI_PLAN_CONFIG  path to a full custom plan configuration JSON (overrides defaults)
#   FAPI_PROVISION_HOOK  path to a script that provisions client JWKS into Keycloak;
#                        invoked with FAPI_CLIENT_JWKS / FAPI_CLIENT2_JWKS file paths
#   FAPI_MAX_POLL     max seconds to poll (default 3600)
#   PLAN_NAME         plan name (default fapi2-security-profile-dpop)
#   ARTIFACTS_DIR     evidence output dir (default artifacts/fapi)
#
# Exit codes: 0 = PASSED (or REVIEW), 1 = FAILED/ERROR/timeout/provisioning required.
set -euo pipefail

FAPI_MODE="${FAPI_MODE:-local}"
case "$FAPI_MODE" in
  local)
    SUITE_URL="${FAPI_SUITE_URL:-https://localhost:8443}"
    SUITE_TOKEN="${FAPI_SUITE_TOKEN:-local-dev-token}"
    ;;
  remote)
    SUITE_URL="${FAPI_SUITE_URL:?FAPI_SUITE_URL is required in remote mode}"
    SUITE_TOKEN="${FAPI_SUITE_TOKEN:?FAPI_SUITE_TOKEN is required in remote mode}"
    ;;
  *)
    echo "::error::FAPI_MODE must be 'local' or 'remote' (got: ${FAPI_MODE})" >&2
    exit 1
    ;;
esac
ISSUER_URL="${ISSUER_URL:?ISSUER_URL is required - must be reachable by the OIDF suite}"
CLIENT_ID="${FAPI_CLIENT_ID:-sentinel-fapi-conformance}"
CLIENT2_ID="${FAPI_CLIENT2_ID:-sentinel-fapi-conformance-mixup}"
PLAN_NAME="${PLAN_NAME:-fapi2-security-profile-dpop}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-artifacts/fapi}"
MAX_POLL="${FAPI_MAX_POLL:-3600}"
POLL_EVERY="${FAPI_POLL_INTERVAL:-15}"
REPORT_DIR="$ARTIFACTS_DIR/report"
JWKS_DIR="$ARTIFACTS_DIR/jwks"

for cmd in jq curl unzip; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "::error::$cmd is required but not installed (preinstalled on GitHub-hosted runners)" >&2
    exit 1
  fi
done

mkdir -p "$REPORT_DIR" "$JWKS_DIR"

# ---------------------------------------------------------------------------
# Pre-flight: the suite must be reachable before we attempt plan creation.
# Local mode serves a self-signed cert via the nginx proxy; -k covers both
# local and remote (hosted suites carry valid CA certs, -k is harmless there).
# ---------------------------------------------------------------------------
echo "==> Pre-flight: verifying suite reachable at ${SUITE_URL}"
SUITE_REACHABLE=false
for _ in $(seq 1 30); do
  if curl -ksf "${SUITE_URL}/api/info" >/dev/null 2>&1; then
    SUITE_REACHABLE=true
    break
  fi
  sleep 2
done
if [ "$SUITE_REACHABLE" != "true" ]; then
  echo "::error::Conformance suite not reachable at ${SUITE_URL} after 30 attempts." >&2
  echo "    Local stack: make fapi-up  (docker compose -f infra/fapi-conformance/docker-compose.yml up -d)" >&2
  exit 1
fi
echo "    suite is up."

# ---------------------------------------------------------------------------
# [1/6] Create the plan.
# The suite API contract (verified against openid/conformance-suite and the
# authentik/credo-ts suite clients): planName and variant are URL query
# parameters, the server/client configuration is the JSON request body, and
# the response carries the plan id under "id".
# ---------------------------------------------------------------------------
VARIANT_JSON='{"openid":"openid_connect","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_profile":"plain_fapi"}'

if [ -n "${FAPI_PLAN_CONFIG:-}" ]; then
  CONFIG_JSON=$(cat "$FAPI_PLAN_CONFIG")
else
  CONFIG_JSON=$(jq -n \
    --arg issuer "$ISSUER_URL/.well-known/openid-configuration" \
    --arg cid "$CLIENT_ID" \
    --arg c2id "$CLIENT2_ID" \
    --arg resource "${RESOURCE_URL:-}" \
    '{server:{discoveryUrl:$issuer}, client:{client_id:$cid, client_name:"Sentinel FAPI Conformance"}, client2:{client_id:$c2id, client_name:"Sentinel FAPI Conformance (mixup)"}} + (if $resource != "" then {resource:{resourceUrl:$resource}} else {} end)')
fi

echo "==> [1/6] Creating FAPI 2.0 plan '${PLAN_NAME}' on ${SUITE_URL}"
echo "    variant: ${VARIANT_JSON}"
PLAN_NAME_ENC=$(jq -rn --arg v "$PLAN_NAME" '$v | @uri')
VARIANT_ENC=$(jq -rn --arg v "$VARIANT_JSON" '$v | @uri')
PLAN_RESPONSE=$(curl -kfsS -X POST "$SUITE_URL/api/plan?planName=${PLAN_NAME_ENC}&variant=${VARIANT_ENC}" \
  -H "Authorization: Bearer $SUITE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$CONFIG_JSON") || {
  echo "::error::Failed to create plan (is FAPI_SUITE_URL/FAPI_SUITE_TOKEN correct?)" >&2
  exit 1
}

PLAN_ID=$(printf '%s' "$PLAN_RESPONSE" | jq -r '.id // .planId // empty')
if [ -z "$PLAN_ID" ]; then
  echo "::error::No plan id in suite response: $(printf '%s' "$PLAN_RESPONSE" | head -c 500)" >&2
  exit 1
fi
echo "==> [2/6] Plan created: ${PLAN_ID}"
echo "    plan page: ${SUITE_URL}/plan-detail.html?plan=${PLAN_ID}"

# ---------------------------------------------------------------------------
# [3/6] Extract the suite-generated client signing JWKS and provision into
# Keycloak (the AS must trust the suite's private_key_jwt keys BEFORE the plan
# is started). The suite generates per-plan keypairs; the plan object carries
# the public JWKS in client.jwks / client2.jwks.
# ---------------------------------------------------------------------------
printf '%s' "$PLAN_RESPONSE" | jq -r '.client.jwks // empty' > "$JWKS_DIR/client-jwks.json" 2>/dev/null || true
printf '%s' "$PLAN_RESPONSE" | jq -r '.client2.jwks // empty' > "$JWKS_DIR/client2-jwks.json" 2>/dev/null || true

if [ ! -s "$JWKS_DIR/client-jwks.json" ]; then
  # Fallback: fetch the plan object if the create response omits the keys.
  PLAN_OBJ=$(curl -kfsS "$SUITE_URL/api/plan/$PLAN_ID" -H "Authorization: Bearer $SUITE_TOKEN" || echo "")
  [ -n "$PLAN_OBJ" ] && printf '%s' "$PLAN_OBJ" | jq -r '.client.jwks // empty' > "$JWKS_DIR/client-jwks.json" 2>/dev/null || true
  [ -n "$PLAN_OBJ" ] && printf '%s' "$PLAN_OBJ" | jq -r '.client2.jwks // empty' > "$JWKS_DIR/client2-jwks.json" 2>/dev/null || true
fi

if [ -s "$JWKS_DIR/client-jwks.json" ]; then
  echo "    extracted suite client JWKS -> $JWKS_DIR"
  if [ -n "${FAPI_PROVISION_HOOK:-}" ]; then
    echo "==> [3b/6] Provisioning client JWKS into Keycloak via ${FAPI_PROVISION_HOOK}"
    FAPI_CLIENT_JWKS="$JWKS_DIR/client-jwks.json" \
    FAPI_CLIENT2_JWKS="$JWKS_DIR/client2-jwks.json" \
    FAPI_CLIENT_ID="$CLIENT_ID" FAPI_CLIENT2_ID="$CLIENT2_ID" \
      bash "$FAPI_PROVISION_HOOK"
  else
    echo "::warning::FAPI_PROVISION_HOOK not set - Keycloak must trust these JWKS manually"
    echo "          before the plan is started, otherwise private_key_jwt fails."
  fi
else
  echo "::warning::Plan response carried no client.jwks; using FAPI_CLIENT_JWKS if provided."
  if [ -n "${FAPI_CLIENT_JWKS:-}" ] && [ -s "${FAPI_CLIENT_JWKS:-/dev/null}" ]; then
    cp "$FAPI_CLIENT_JWKS" "$JWKS_DIR/client-jwks.json"
  fi
  if [ -n "${FAPI_CLIENT2_JWKS:-}" ] && [ -s "${FAPI_CLIENT2_JWKS:-/dev/null}" ]; then
    cp "$FAPI_CLIENT2_JWKS" "$JWKS_DIR/client2-jwks.json"
  fi
fi

# ---------------------------------------------------------------------------
# [4/6] Start the plan (idempotent; 4xx if already started) and poll the
# plan-level aggregate result.
# ---------------------------------------------------------------------------
STARTED=$(curl -kfsS "$SUITE_URL/api/plan/$PLAN_ID" -H "Authorization: Bearer $SUITE_TOKEN" 2>/dev/null \
  | jq -r '.started // false' 2>/dev/null || echo false)
if [ "$STARTED" != "true" ]; then
  echo "==> [4/6] Starting plan ${PLAN_ID}"
  curl -kfsS -X POST "$SUITE_URL/api/plan/$PLAN_ID/start" -H "Authorization: Bearer $SUITE_TOKEN" >/dev/null 2>&1 \
    || echo "::warning::start endpoint not available (4xx) - plan may auto-run; continuing to poll."
else
  echo "==> [4/6] Plan already started."
fi

echo "==> [5/6] Polling plan result (every ${POLL_EVERY}s, up to ${MAX_POLL}s)"
STATUS=""
RESULT_JSON=""
for _ in $(seq 1 $((MAX_POLL / POLL_EVERY))); do
  RESULT_JSON=$(curl -kfsS "$SUITE_URL/api/plan/$PLAN_ID/result" \
    -H "Authorization: Bearer $SUITE_TOKEN" -H 'Accept: application/json' || echo "{}")
  STATUS=$(printf '%s' "$RESULT_JSON" | jq -r '.result // "RUNNING"' 2>/dev/null || echo "RUNNING")
  echo "    status: ${STATUS}"
  case "$STATUS" in
    PASSED|FAILED|REVIEW|ERROR|INTERRUPTED|COMPLETED) break ;;
  esac
  sleep "$POLL_EVERY"
done

if [ "$STATUS" != "PASSED" ] && [ "$STATUS" != "FAILED" ] && [ "$STATUS" != "REVIEW" ] && \
   [ "$STATUS" != "ERROR" ] && [ "$STATUS" != "INTERRUPTED" ] && [ "$STATUS" != "COMPLETED" ]; then
  echo "::error::FAPI conformance timed out after ${MAX_POLL}s (last status: ${STATUS})" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# [6/6] Evidence chain of custody: export the HTML report pack, snapshot the
# result JSON, download the certificate on PASS, verify integrity, and write a
# SHA-256 manifest tying every artifact to the plan and this run.
# ---------------------------------------------------------------------------
echo "==> [6/6] Downloading and verifying evidence artifacts"
printf '%s' "$RESULT_JSON" > "$ARTIFACTS_DIR/fapi-result.json"

EXPORT_ZIP="$ARTIFACTS_DIR/fapi-report.zip"
if curl -kfsS "$SUITE_URL/api/plan/exporthtml/$PLAN_ID" -H "Authorization: Bearer $SUITE_TOKEN" \
    -o "$EXPORT_ZIP" 2>/dev/null; then
  (cd "$REPORT_DIR" && unzip -oq "$EXPORT_ZIP" 2>/dev/null) || echo "::warning::report zip is not a valid archive"
  echo "    report pack: $EXPORT_ZIP (+ extracted $REPORT_DIR)"
else
  echo "::warning::report export unavailable (plan may not be finished); continuing."
fi

CERT_FILE="$ARTIFACTS_DIR/fapi-certificate.pdf"
if [ "$STATUS" = "PASSED" ] || [ "$STATUS" = "COMPLETED" ]; then
  if curl -kfsS "$SUITE_URL/api/plan/$PLAN_ID/certificate" \
      -H "Authorization: Bearer $SUITE_TOKEN" -H 'Accept: application/pdf' \
      -o "$CERT_FILE" 2>/dev/null && [ -s "$CERT_FILE" ]; then
    if [ "$(head -c 4 "$CERT_FILE")" = "%PDF" ]; then
      echo "    certificate: $CERT_FILE (valid PDF)"
    else
      echo "::warning::certificate file is not a PDF (magic bytes missing) - not archived as evidence."
      rm -f "$CERT_FILE"
    fi
  else
    echo "::warning::certificate download failed - certificate may be issued asynchronously."
  fi
fi

# Chain-of-custody manifest (SHA-256 of every artifact + run provenance).
{
  echo "FAPI 2.0 CONFORMANCE EVIDENCE MANIFEST"
  echo "generated:      $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "suite_url:      ${SUITE_URL}"
  echo "plan_name:      ${PLAN_NAME}"
  echo "plan_id:        ${PLAN_ID}"
  echo "plan_page:      ${SUITE_URL}/plan-detail.html?plan=${PLAN_ID}"
  echo "issuer:         ${ISSUER_URL}"
  echo "result:         ${STATUS}"
  echo "variant:        ${VARIANT_JSON}"
  echo "sha256:"
  find "$ARTIFACTS_DIR" -type f -not -name 'fapi-evidence-manifest.txt' -print0 \
    | sort -z | xargs -0 sha256sum | sed "s|$ARTIFACTS_DIR/|    |"
} > "$ARTIFACTS_DIR/fapi-evidence-manifest.txt"

if [ "$STATUS" = "PASSED" ] || [ "$STATUS" = "COMPLETED" ]; then
  echo "==> FAPI 2.0 Conformance: PASSED. Certificate + evidence archived in ${ARTIFACTS_DIR}"
  exit 0
elif [ "$STATUS" = "REVIEW" ]; then
  echo "::warning::FAPI 2.0 Conformance requires manual review (REVIEW). Evidence archived; audit the report before release."
  exit 0
else
  echo "::error::FAPI 2.0 Conformance ${STATUS} - release blocked. Inspect ${ARTIFACTS_DIR}/fapi-result.json"
  printf '%s' "$RESULT_JSON" | jq -r '.modules[]? | select(.result != "PASSED") | "    FAILING MODULE: \(.testModule // .name) -> \(.result)"' 2>/dev/null \
    | head -40 || true
  echo "::error::Plan detail: ${SUITE_URL}/plan-detail.html?plan=${PLAN_ID}" >&2
  exit 1
fi
