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
#   FAPI_CLIENT_PRIVATE_JWKS / FAPI_CLIENT2_PRIVATE_JWKS
#                        optional private JWKS files; generated ephemerally when omitted
#   FAPI_CLIENT_JWKS / FAPI_CLIENT2_JWKS
#                        optional public JWKS files for Keycloak provisioning; generated when omitted
#   FAPI_MAX_POLL     max seconds to poll (default 3600)
#   PLAN_NAME         plan name (default fapi2-security-profile-final-test-plan)
#   ARTIFACTS_DIR     evidence output dir (default artifacts/fapi)
#
# Exit codes: 0 = PASSED (or REVIEW), 1 = FAILED/ERROR/timeout/provisioning required.
set -euo pipefail

# Load local settings when invoked from PowerShell through WSL/Git Bash.
# Existing environment variables win and .env values only fill missing values.
FAPI_ENV_FILE="${FAPI_ENV_FILE:-infra/fapi-conformance/.env}"
if [ -f "$FAPI_ENV_FILE" ]; then
  while IFS='=' read -r env_name env_value; do
    case "$env_name" in
      ''|\#*) continue ;;
    esac
    if [ -z "${!env_name+x}" ]; then
      export "$env_name=$env_value"
    fi
  done < "$FAPI_ENV_FILE"
fi

FAPI_MODE="${FAPI_MODE:-local}"
case "$FAPI_MODE" in
  local)
    SUITE_URL="${FAPI_SUITE_URL:-https://localhost:${FAPI_PROXY_PORT:-8443}}"
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
ISSUER_URL="${ISSUER_URL:-${KEYCLOAK_ISSUER:-}}"
ISSUER_URL="${ISSUER_URL:?ISSUER_URL or KEYCLOAK_ISSUER is required - must be reachable by the OIDF suite}"
CLIENT_ID="${FAPI_CLIENT_ID:-sentinel-fapi-conformance}"
CLIENT2_ID="${FAPI_CLIENT2_ID:-sentinel-fapi-conformance-mixup}"
PLAN_NAME="${PLAN_NAME:-${FAPI_PLAN_NAME:-fapi2-security-profile-final-test-plan}}"
RESOURCE_URL="${RESOURCE_URL:-${SENTINEL_API_URL:-}}"
if [ "$FAPI_MODE" = "local" ]; then
  FAPI_PROVISION_HOOK="${FAPI_PROVISION_HOOK:-infra/keycloak/scripts/provision-fapi-conformance-clients.sh}"
  DOCKER_FALLBACK="${DOCKER_FALLBACK:-true}"
  KC_TRUSTSTORE_HOST="${KC_TRUSTSTORE_HOST:-$(pwd)/infra/fapi-conformance/certs/truststore.p12}"
  KC_TRUSTSTORE_PASS="${KC_TRUSTSTORE_PASS:-${FAPI_KEYSTORE_PASSWORD:-sentinel-fapi}}"
  export FAPI_PROVISION_HOOK DOCKER_FALLBACK KC_TRUSTSTORE_HOST KC_TRUSTSTORE_PASS
fi
# In local dev mode the suite injects a dummy user (SPRING_PROFILES_ACTIVE=dev)
# so the API token is not required and sending a Bearer token triggers
# OAuth resource-server validation (401). Only send the header in remote mode.
AUTH_HDR=()
if [ "$FAPI_MODE" = "remote" ]; then
  AUTH_HDR=(-H "Authorization: Bearer $SUITE_TOKEN")
fi
ARTIFACTS_DIR="${ARTIFACTS_DIR:-artifacts/fapi}"
MAX_POLL="${FAPI_MAX_POLL:-3600}"
POLL_EVERY="${FAPI_POLL_INTERVAL:-15}"
REPORT_DIR="$ARTIFACTS_DIR/report"
JWKS_DIR="$ARTIFACTS_DIR/jwks"

for cmd in jq curl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "::error::$cmd is required but not installed (preinstalled on GitHub-hosted runners)" >&2
    exit 1
  fi
done
if ! command -v unzip >/dev/null 2>&1; then
  echo "::warning::unzip not found - report extraction will be skipped (install unzip for full evidence pack)" >&2
fi

mkdir -p "$REPORT_DIR" "$JWKS_DIR"

if { [ -n "${FAPI_CLIENT_PRIVATE_JWKS:-}" ] && [ -z "${FAPI_CLIENT_JWKS:-}" ]; } || \
   { [ -z "${FAPI_CLIENT_PRIVATE_JWKS:-}" ] && [ -n "${FAPI_CLIENT_JWKS:-}" ]; } || \
   { [ -n "${FAPI_CLIENT2_PRIVATE_JWKS:-}" ] && [ -z "${FAPI_CLIENT2_JWKS:-}" ]; } || \
   { [ -z "${FAPI_CLIENT2_PRIVATE_JWKS:-}" ] && [ -n "${FAPI_CLIENT2_JWKS:-}" ]; }; then
  echo "::error::Each FAPI client requires both matching private and public JWKS files." >&2
  exit 1
fi

# Current local suite images require private client signing keys in the plan
# configuration. Generate ephemeral keys per run unless callers provide them.
if [ -z "${FAPI_CLIENT_PRIVATE_JWKS:-}" ] || [ -z "${FAPI_CLIENT2_PRIVATE_JWKS:-}" ]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "::error::python3 is required to generate ephemeral FAPI client JWKS." >&2
    exit 1
  fi
  PRIVATE_JWKS_DIR="${TMPDIR:-/tmp}/sentinel-fapi-jwks-$$"
  mkdir -m 700 "$PRIVATE_JWKS_DIR"
  trap 'rm -rf "$PRIVATE_JWKS_DIR"' EXIT
  python3 - "$PRIVATE_JWKS_DIR" "$JWKS_DIR" <<'PY'
import base64, hashlib, json, os, sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def b64u(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")

def generate(path, public_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key()
    numbers = public.public_numbers()
    private = key.private_numbers()
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    kid = b64u(hashlib.sha256(der).digest())
    jwk = {
        "kty": "RSA", "kid": kid, "use": "sig", "alg": "PS256",
        "n": b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        "d": b64u(private.d.to_bytes((private.d.bit_length() + 7) // 8, "big")),
        "p": b64u(private.p.to_bytes((private.p.bit_length() + 7) // 8, "big")),
        "q": b64u(private.q.to_bytes((private.q.bit_length() + 7) // 8, "big")),
        "dp": b64u(private.dmp1.to_bytes((private.dmp1.bit_length() + 7) // 8, "big")),
        "dq": b64u(private.dmq1.to_bytes((private.dmq1.bit_length() + 7) // 8, "big")),
        "qi": b64u(private.iqmp.to_bytes((private.iqmp.bit_length() + 7) // 8, "big")),
    }
    with open(path, "w") as f:
        json.dump({"keys": [jwk]}, f)
    with open(public_path, "w") as f:
        json.dump({"keys": [{k: jwk[k] for k in ("kty", "kid", "use", "alg", "n", "e")}]}, f)

private_root = sys.argv[1]
public_root = sys.argv[2]
generate(os.path.join(private_root, "client-private-jwks.json"), os.path.join(public_root, "client-jwks.json"))
generate(os.path.join(private_root, "client2-private-jwks.json"), os.path.join(public_root, "client2-jwks.json"))
PY
  FAPI_CLIENT_PRIVATE_JWKS="${FAPI_CLIENT_PRIVATE_JWKS:-$PRIVATE_JWKS_DIR/client-private-jwks.json}"
  FAPI_CLIENT2_PRIVATE_JWKS="${FAPI_CLIENT2_PRIVATE_JWKS:-$PRIVATE_JWKS_DIR/client2-private-jwks.json}"
  FAPI_CLIENT_JWKS="${FAPI_CLIENT_JWKS:-$JWKS_DIR/client-jwks.json}"
  FAPI_CLIENT2_JWKS="${FAPI_CLIENT2_JWKS:-$JWKS_DIR/client2-jwks.json}"
fi

# ---------------------------------------------------------------------------
# Pre-flight: the suite must be reachable before we attempt plan creation.
# Local mode serves a self-signed cert via the nginx proxy; -k covers both
# local and remote (hosted suites carry valid CA certs, -k is harmless there).
# ---------------------------------------------------------------------------
echo "==> Pre-flight: verifying suite reachable at ${SUITE_URL}"
SUITE_REACHABLE=false
for _ in $(seq 1 30); do
  if curl -ksf "${SUITE_URL}/actuator/health" >/dev/null 2>&1 || curl -ksf "${SUITE_URL}/api/info" >/dev/null 2>&1; then
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
# The suite needs the private signing keys in the plan configuration. These
# optional files are also useful with local suite images that do not generate
# client keys automatically.
if [ -n "${FAPI_CLIENT_PRIVATE_JWKS:-}" ]; then
  CONFIG_JSON=$(printf '%s' "$CONFIG_JSON" | jq --slurpfile jwks "$FAPI_CLIENT_PRIVATE_JWKS" '.client.jwks = $jwks[0]')
fi
if [ -n "${FAPI_CLIENT2_PRIVATE_JWKS:-}" ]; then
  CONFIG_JSON=$(printf '%s' "$CONFIG_JSON" | jq --slurpfile jwks "$FAPI_CLIENT2_PRIVATE_JWKS" '.client2.jwks = $jwks[0]')
fi

echo "==> [1/6] Creating FAPI 2.0 plan '${PLAN_NAME}' on ${SUITE_URL}"
echo "    variant: ${VARIANT_JSON}"
PLAN_NAME_ENC=$(jq -rn --arg v "$PLAN_NAME" '$v | @uri')
VARIANT_ENC=$(jq -rn --arg v "$VARIANT_JSON" '$v | @uri')
PLAN_RESPONSE=$(curl -kfsS -X POST "$SUITE_URL/api/plan?planName=${PLAN_NAME_ENC}&variant=${VARIANT_ENC}" \
  "${AUTH_HDR[@]}" \
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
# [3/6] Provision the per-run client signing JWKS into Keycloak. The AS must
# trust the public keys before private_key_jwt tests start; the current local
# suite image does not generate these keys automatically.
# ---------------------------------------------------------------------------
if [ -n "${FAPI_CLIENT_JWKS:-}" ] && [ -s "$FAPI_CLIENT_JWKS" ]; then
  if [ "$FAPI_CLIENT_JWKS" != "$JWKS_DIR/client-jwks.json" ]; then
    cp "$FAPI_CLIENT_JWKS" "$JWKS_DIR/client-jwks.json"
  fi
else
  printf '%s' "$PLAN_RESPONSE" | jq -r '.client.jwks // empty' > "$JWKS_DIR/client-jwks.json" 2>/dev/null || true
fi
if [ -n "${FAPI_CLIENT2_JWKS:-}" ] && [ -s "$FAPI_CLIENT2_JWKS" ]; then
  if [ "$FAPI_CLIENT2_JWKS" != "$JWKS_DIR/client2-jwks.json" ]; then
    cp "$FAPI_CLIENT2_JWKS" "$JWKS_DIR/client2-jwks.json"
  fi
else
  printf '%s' "$PLAN_RESPONSE" | jq -r '.client2.jwks // empty' > "$JWKS_DIR/client2-jwks.json" 2>/dev/null || true
fi
if [ -n "${FAPI_PROVISION_HOOK:-}" ]; then
  if [ ! -s "$JWKS_DIR/client-jwks.json" ] || [ ! -s "$JWKS_DIR/client2-jwks.json" ]; then
    echo "::error::Both public client JWKS files are required for FAPI_PROVISION_HOOK provisioning." >&2
    exit 1
  fi
  echo "==> [3b/6] Provisioning client JWKS into Keycloak via ${FAPI_PROVISION_HOOK}"
  FAPI_CLIENT_JWKS="$JWKS_DIR/client-jwks.json" \
  FAPI_CLIENT2_JWKS="$JWKS_DIR/client2-jwks.json" \
  FAPI_CLIENT_ID="$CLIENT_ID" FAPI_CLIENT2_ID="$CLIENT2_ID" \
    bash "$FAPI_PROVISION_HOOK"
fi

# ---------------------------------------------------------------------------
# [4/6] Create one runner instance per module. The current suite executes
# plans through /api/runner and exposes status/results through /api/info.
# ---------------------------------------------------------------------------
RUNNERS_FILE="$ARTIFACTS_DIR/runner-ids.tsv"
: > "$RUNNERS_FILE"
MODULES_JSON=$(printf '%s' "$PLAN_RESPONSE" | jq -c '.modules // []')
MODULE_COUNT=$(printf '%s' "$MODULES_JSON" | jq 'length')
[ "$MODULE_COUNT" -gt 0 ] || { echo "::error::Plan contains no test modules." >&2; exit 1; }

echo "==> [4/6] Creating ${MODULE_COUNT} test module runners"
while IFS=$'\t' read -r module variant; do
  [ -n "$module" ] || continue
  MODULE_ENC=$(jq -rn --arg v "$module" '$v | @uri')
  VARIANT_ENC=$(jq -rn --arg v "$variant" '$v | @uri')
  RUNNER_RESPONSE=$(curl -kfsS -X POST "$SUITE_URL/api/runner?test=${MODULE_ENC}&plan=${PLAN_ID}&variant=${VARIANT_ENC}" \
    "${AUTH_HDR[@]}") || { echo "::error::Failed to create runner for ${module}" >&2; exit 1; }
  RUNNER_ID=$(printf '%s' "$RUNNER_RESPONSE" | jq -r '.id // empty')
  [ -n "$RUNNER_ID" ] || { echo "::error::No runner id for ${module}: $RUNNER_RESPONSE" >&2; exit 1; }
  printf '%s\t%s\n' "$RUNNER_ID" "$module" >> "$RUNNERS_FILE"
done < <(printf '%s' "$MODULES_JSON" | jq -r '.[] | [.testModule, ((.variant // {}) | tojson)] | @tsv')

echo "==> [5/6] Polling module results (every ${POLL_EVERY}s, up to ${MAX_POLL}s)"
DEADLINE=$(( $(date +%s) + MAX_POLL ))
RESULT_JSON='[]'
STATUS="RUNNING"
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  RESULT_JSON='[]'
  ALL_FINISHED=true
  while IFS=$'\t' read -r runner_id module; do
    INFO=$(curl -kfsS "$SUITE_URL/api/info/$runner_id" "${AUTH_HDR[@]}" || echo '{}')
    RESULT_JSON=$(jq -c --arg module "$module" --arg id "$runner_id" --argjson info "$INFO" '. + [{module:$module,id:$id,status:($info.status // "UNKNOWN"),result:($info.result // null)}]' <<< "$RESULT_JSON")
    state=$(printf '%s' "$INFO" | jq -r '.status // "UNKNOWN"')
    case "$state" in FINISHED|INTERRUPTED) ;; *) ALL_FINISHED=false ;; esac
  done < "$RUNNERS_FILE"
  echo "    completed: $(printf '%s' "$RESULT_JSON" | jq '[.[] | select(.status == "FINISHED" or .status == "INTERRUPTED")] | length')/${MODULE_COUNT}"
  if [ "$ALL_FINISHED" = true ]; then break; fi
  sleep "$POLL_EVERY"
done
if [ "$ALL_FINISHED" != true ]; then
  STATUS="ERROR"
  echo "::error::FAPI conformance timed out after ${MAX_POLL}s" >&2
else
  STATUS=$(printf '%s' "$RESULT_JSON" | jq -r 'if any(.[]; .result == "FAILED" or .result == "UNKNOWN") then "FAILED" elif any(.[]; .result == "REVIEW" or .result == "WARNING") then "REVIEW" else "PASSED" end')
fi

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
if curl -kfsS "$SUITE_URL/api/plan/exporthtml/$PLAN_ID" "${AUTH_HDR[@]}" \
    -o "$EXPORT_ZIP" 2>/dev/null; then
  if command -v unzip >/dev/null 2>&1; then
    (cd "$REPORT_DIR" && unzip -oq "$EXPORT_ZIP" 2>/dev/null) || echo "::warning::report zip is not a valid archive"
  else
    python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$EXPORT_ZIP" "$REPORT_DIR" 2>/dev/null || echo "::warning::report zip extraction failed (python fallback)"
  fi
  echo "    report pack: $EXPORT_ZIP (+ extracted $REPORT_DIR)"
else
  echo "::warning::report export unavailable (plan may not be finished); continuing."
fi

CERT_FILE="$ARTIFACTS_DIR/fapi-certificate.pdf"
if [ "$STATUS" = "PASSED" ] || [ "$STATUS" = "COMPLETED" ]; then
  if curl -kfsS "$SUITE_URL/api/plan/$PLAN_ID/certificate" \
      "${AUTH_HDR[@]}" -H 'Accept: application/pdf' \
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
