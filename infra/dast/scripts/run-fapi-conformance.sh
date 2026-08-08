#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# run-fapi-conformance.sh - OIDF FAPI 2.0 Conformance pre-audit gate.
#
# Executes the OpenID Foundation FAPI 2.0 Conformance Test Suite
# (Security Profile + DPoP variant) against the sentinel-dast Keycloak.
# The conformance PASSED result is a mandatory prerequisite before the annual
# independent audit can be scheduled (§3.8 / KPI "FAPI conformance suite").
#
# Required environment:
#   FAPI_SUITE_URL   base URL of the conformance instance (hosted or self)
#   FAPI_SUITE_TOKEN API token for plan creation
#   ISSUER_URL       staging issuer (default sentinel-dast realm)
set -euo pipefail

SUITE_URL="${FAPI_SUITE_URL:?}"
SUITE_TOKEN="${FAPI_SUITE_TOKEN:?}"
ISSUER_URL="${ISSUER_URL:-https://keycloak.staging.sentinel.local/realms/sentinel-dast}"
PLAN_NAME="${PLAN_NAME:-fapi2-security-profile-dpop}"

echo "==> creating FAPI 2.0 conformance plan '${PLAN_NAME}' on ${SUITE_URL}"
PLAN_RESPONSE=$(curl -fsS -X POST "$SUITE_URL/api/plan" \
  -H "Authorization: Bearer $SUITE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{
    \"planName\": \"$PLAN_NAME\",
    \"server\": {
      \"issuer\": \"$ISSUER_URL\",
      \"jwks_uri\": \"auto\",
      \"dpop\": true
    },
    \"client\": { \"client_name\": \"sentinel-conformance\" }
  }")

PLAN_ID=$(printf '%s' "$PLAN_RESPONSE" | python3 -c 'import json,sys;print(json.load(sys.stdin)["planId"])' 2>/dev/null || \
          printf '%s' "$PLAN_RESPONSE" | node -e 'const d=JSON.parse(require("fs").readFileSync(0));console.log(d.planId)')
echo "==> plan created: ${PLAN_ID}"

MAX_POLL=${FAPI_MAX_POLL:-3600}
POLL_EVERY=15
for _ in $(seq 1 $((MAX_POLL / POLL_EVERY))); do
  RESULT=$(curl -fsS "$SUITE_URL/api/plan/$PLAN_ID/result" -H "Authorization: Bearer $SUITE_TOKEN")
  STATUS=$(printf '%s' "$RESULT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"])' 2>/dev/null || echo RUNNING)
  echo "[fapi] status=${STATUS}"
  if [ "$STATUS" = "PASSED" ]; then
    echo "==> FAPI 2.0 conformance: PASSED"
    exit 0
  fi
  if [ "$STATUS" = "FAILED" ] || [ "$STATUS" = "ERROR" ]; then
    echo "::error::FAPI 2.0 conformance ${STATUS} - release/audit gate blocked" >&2
    exit 1
  fi
  sleep $POLL_EVERY
done

echo "::error::FAPI conformance timed out after ${MAX_POLL}s" >&2
exit 1