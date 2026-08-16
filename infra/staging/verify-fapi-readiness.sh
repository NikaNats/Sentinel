#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# verify-fapi-readiness.sh - pre-flight verification that the staging Keycloak
# is ready for a FAPI 2.0 OIDF Conformance Suite run (DOC-0017 Phase 3).
#
# Runs before the authoritative gate starts a plan so the run fails fast with
# an actionable triage message instead of burning a certification attempt on a
# misconfigured AS. Eight checks:
#
#   1. discovery document reachable and issuer matches KEYCLOAK_ISSUER
#   2. PAR endpoint advertised (pushed_authorization_request_endpoint)
#   3. realm signing keys advertise PS256 (and only allowed algorithms)
#   4. client policy bindings present (count > 0)
#   5. client profiles present (count > 0)
#   6. DPoP feature enabled (serverinfo)
#   7. PAR feature enabled (serverinfo)
#   8. TLS 1.3 handshake succeeds (openssl s_client)
#
# Required environment:
#   KEYCLOAK_URL         e.g. https://keycloak.staging.sentinel.io/realms/sentinel-dast
#   KC_ADMIN_URL         Keycloak base URL (origin only)
#   KC_ADMIN_USER / KC_ADMIN_PASSWORD   admin credentials (or KC_ADMIN_TOKEN)
#   REALM                realm to verify (default sentinel-dast)
#
# Requirements: curl, jq, openssl.
set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:?KEYCLOAK_URL is required (e.g. https://host/realms/sentinel-dast)}"
KC_ADMIN_URL="${KC_ADMIN_URL:?KC_ADMIN_URL is required (origin of the admin API)}"
REALM="${REALM:-sentinel-dast}"
ADMIN_USER="${KC_ADMIN_USER:-}"
ADMIN_PASSWORD="${KC_ADMIN_PASSWORD:-}"
ADMIN_TOKEN="${KC_ADMIN_TOKEN:-}"
VERIFY_TLS="${VERIFY_TLS:-true}"

command -v curl >/dev/null 2>&1 || { echo "error: curl is required" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "error: openssl is required" >&2; exit 2; }

TMPDIR_R="${TMPDIR:-/tmp}/fapi-readiness.$$"
mkdir -p "$TMPDIR_R"
trap 'rm -rf "$TMPDIR_R"' EXIT

PASS=0
FAIL=0

check() {
    local name="$1" rc=0
    shift
    if "$@" >"$TMPDIR_R/out" 2>&1; then
        PASS=$((PASS + 1))
        echo "[PASS] $name"
    else
        rc=$?
        FAIL=$((FAIL + 1))
        echo "[FAIL] $name"
        sed 's/^/       /' "$TMPDIR_R/out" | tail -n 4
    fi
    return 0
}

fail_here() {
    echo "[FAIL] $1"
    sed 's/^/       /' <<<"$2" | tail -n 4
    FAIL=$((FAIL + 1))
}

echo "==> acquiring admin token"
if [[ -z "$ADMIN_TOKEN" ]]; then
    [[ -n "$ADMIN_USER" && -n "$ADMIN_PASSWORD" ]] || {
        echo "error: KC_ADMIN_USER/KC_ADMIN_PASSWORD or KC_ADMIN_TOKEN is required" >&2
        exit 2
    }
    ADMIN_TOKEN=$(curl -fsS \
        -d "client_id=admin-cli" \
        -d "grant_type=password" \
        -d "username=$ADMIN_USER" \
        -d "password=$ADMIN_PASSWORD" \
        "$KC_ADMIN_URL/realms/master/protocol/openid-connect/token" \
        | jq -r '.access_token')
fi

# 1. discovery document
check "discovery document (200 + issuer match)" \
    curl -fsS "$KEYCLOAK_URL/.well-known/openid-configuration" \
    | jq -e --arg e "$KEYCLOAK_URL" '.issuer == $e'

# 2. PAR endpoint
check "PAR endpoint advertised" \
    curl -fsS "$KEYCLOAK_URL/.well-known/openid-configuration" \
    | jq -e '.pushed_authorization_request_endpoint | length > 0'

# 3. signing keys: PS256 present, no algorithm confusion (RS256 forbidden)
check "realm keys advertise PS256 only/with ES256 (no RS256)" \
    curl -fsS "$KEYCLOAK_URL/protocol/openid-connect/certs" \
    | jq -e '.keys | map(.alg) | unique | index("PS256") != null and (index("RS256") == null)'

# 4/5. client policies + profiles (admin API)
check "client policies bound (count > 0)" \
    curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$KC_ADMIN_URL/admin/realms/$REALM/client-policies/policies" \
    | jq -e '.policies | length > 0'

check "client profiles present (count > 0)" \
    curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$KC_ADMIN_URL/admin/realms/$REALM/client-policies/profiles" \
    | jq -e '.profiles | length > 0'

# 6/7. DPoP + PAR features (serverinfo)
check "DPoP feature enabled" \
    curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$KC_ADMIN_URL/admin/serverinfo" \
    | jq -e '.features | index("DPoP") != null'

check "PAR feature enabled" \
    curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$KC_ADMIN_URL/admin/serverinfo" \
    | jq -e '.features | index("PAR") != null'

# 8. TLS 1.3 (the suite rejects the connection otherwise)
if [[ "$VERIFY_TLS" == "true" ]]; then
    HOST_PORT="${KEYCLOAK_URL#https://}"
    HOST_PORT="${HOST_PORT%%/*}"
    check "TLS 1.3 handshake + public CA chain validity ($HOST_PORT)" \
        openssl s_client -connect "$HOST_PORT" -servername "${HOST_PORT%%:*}" \
            -tls1_3 -brief -verify 1 -verify_return_error </dev/null
else
    echo "[SKIP] TLS 1.3 handshake (VERIFY_TLS=false)"
fi

echo
echo "==> readiness summary: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
