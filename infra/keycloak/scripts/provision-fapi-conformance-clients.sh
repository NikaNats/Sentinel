#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# provision-fapi-conformance-clients.sh - registers the OIDF Conformance clients
# in Keycloak with the exact FAPI 2.0 posture the suite exercises.
#
# The OIDF suite generates a per-plan signing keypair and uses private_key_jwt
# client authentication. Keycloak must trust those public keys BEFORE the plan
# starts - hence this hook is driven by run-fapi-conformance.sh (FAPI_PROVISION_HOOK),
# which passes the suite-extracted JWKS files as FAPI_CLIENT_JWKS/FAPI_CLIENT2_JWKS.
#
# TWO clients are registered (the suite tests client mixup attacks and requires
# distinct keys per client - see https://openid.net/certification/certification-fapi_op_testing/):
#   sentinel-fapi-conformance          (primary)
#   sentinel-fapi-conformance-mixup    (second client, different key)
#
# Required environment:
#   KC_ADMIN_URL         Keycloak base URL (e.g. https://keycloak.staging.sentinel.io)
#   KC_REALM             realm to provision into (default sentinel-dast)
#   KC_ADMIN_USER / KC_ADMIN_PASSWORD  or  KC_ADMIN_TOKEN (master realm)
#   FAPI_CLIENT_JWKS     path to the suite-generated public JWKS for client 1
#   FAPI_CLIENT2_JWKS    path to the suite-generated public JWKS for client 2
#   FAPI_CLIENT_ID / FAPI_CLIENT2_ID  client ids (defaults match run-fapi-conformance.sh)
#   KCADM_BIN            optional explicit path to kcadm.sh
#
# Requirements: python3 + the `cryptography` package (JWKS -> PEM conversion;
# preinstalled on GitHub-hosted ubuntu runners), or the Keycloak admin console
# for manual JWKS upload (see docs/OIDF_FAPI_CONFORMANCE_RUNBOOK.md).
set -euo pipefail

KC_ADMIN_URL="${KC_ADMIN_URL:?KC_ADMIN_URL is required}"
KC_REALM="${KC_REALM:-sentinel-dast}"
CLIENT_ID="${FAPI_CLIENT_ID:-sentinel-fapi-conformance}"
CLIENT2_ID="${FAPI_CLIENT2_ID:-sentinel-fapi-conformance-mixup}"
JWKS1="${FAPI_CLIENT_JWKS:?FAPI_CLIENT_JWKS is required}"
JWKS2="${FAPI_CLIENT2_JWKS:?FAPI_CLIENT2_JWKS is required}"

# Optional: trust the local CA that signs the dev Keycloak cert.
#   KC_TRUSTSTORE_HOST  host path to a PKCS12 truststore containing the CA
#                       (local: infra/fapi-conformance/certs/truststore.p12)
#   KC_TRUSTSTORE_PASS  truststore password (default sentinel-fapi)
KC_TRUSTSTORE_HOST="${KC_TRUSTSTORE_HOST:-}"
KC_TRUSTSTORE_PASS="${KC_TRUSTSTORE_PASS:-sentinel-fapi}"

KCADM="${KCADM_BIN:-kcadm.sh}"
DOCKER_FALLBACK="${DOCKER_FALLBACK:-}"
TRUSTSTORE_IN_CONTAINER="/truststore/truststore.p12"

if ! command -v "$KCADM" >/dev/null 2>&1; then
  if [ "$DOCKER_FALLBACK" = "true" ] && command -v docker >/dev/null 2>&1; then
    # kcadm persists its session under Java user.home (the passwd home of the
    # uid; the image's keycloak user has home=/opt/keycloak, root=/root). A
    # named volume at /root/.keycloak keeps the session across the --rm
    # invocations (each kcadm call is a separate container).
    # --network host lets the container reach a local Keycloak at
    # https://localhost:8443; the truststore is mounted read-only.
    KCADM="docker run --rm -u root --network host -v kcadm-credentials:/root/.keycloak"
    if [ -n "$KC_TRUSTSTORE_HOST" ]; then
      KCADM="$KCADM -v $KC_TRUSTSTORE_HOST:$TRUSTSTORE_IN_CONTAINER:ro"
    fi
    KCADM="$KCADM --entrypoint /opt/keycloak/bin/kcadm.sh quay.io/keycloak/keycloak:26.6.4"
  else
    echo "::error::kcadm.sh not found. Install the Keycloak CLI, set KCADM_BIN, or use DOCKER_FALLBACK=true." >&2
    exit 1
  fi
fi

# Wrapper keeps "$@" quoted (no eval): KC_ADMIN_PASSWORD may contain shell
# metacharacters. $KCADM expands unquoted by design - it can be a multi-word
# docker command string; its value is operator-controlled, never a secret.
# Under MSYS (Git Bash on Windows) docker.exe path-converts /opt/... into a
# Windows path; MSYS_NO_PATHCONV=1 keeps the in-container path intact.
# KC_TRUST_ARGS: when a truststore is supplied, kcadm trusts the local CA
# (host kcadm uses the host path; the docker fallback uses the mount path).
if [ -n "$KC_TRUSTSTORE_HOST" ]; then
  if [ -z "$DOCKER_FALLBACK" ] || [ "$DOCKER_FALLBACK" != "true" ]; then
    KC_TRUST_ARGS=(--truststore "$KC_TRUSTSTORE_HOST" --trustpass "$KC_TRUSTSTORE_PASS")
  else
    KC_TRUST_ARGS=(--truststore "$TRUSTSTORE_IN_CONTAINER" --trustpass "$KC_TRUSTSTORE_PASS")
  fi
else
  KC_TRUST_ARGS=()
fi

if [ -n "${MSYSTEM:-}" ]; then
  kcadm() { MSYS_NO_PATHCONV=1 $KCADM "${KC_TRUST_ARGS[@]}" "$@"; }
else
  kcadm() { $KCADM "${KC_TRUST_ARGS[@]}" "$@"; }
fi

# python3 is a Windows Store alias stub under Git Bash; prefer the real interpreter.
if command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
  PYTHON_CMD="python3"
else
  PYTHON_CMD="python"
fi

# JWKS -> SPKI PEM for the Keycloak static public-key attribute
# (clientAuthenticatorType=client-jwt accepts a PEM public key via the REST API).
if ! $PYTHON_CMD -c "import cryptography" >/dev/null 2>&1; then
  echo "::warning::Python 'cryptography' package missing - attempting pip3 install" >&2
  if ! pip3 install --quiet cryptography; then
    echo "::error::Failed to install 'cryptography'. Run the provisioner manually with a prepared PEM (see docs/OIDF_FAPI_CONFORMANCE_RUNBOOK.md)." >&2
    exit 1
  fi
fi

convert_jwks_to_pem() {
  $PYTHON_CMD - "$1" <<'PY'
import base64, json, sys
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

with open(sys.argv[1], "r") as f:
    jwks = json.load(f)
keys = jwks.get("keys", [])
if not keys:
    raise SystemExit("JWKS contains no keys")
key = keys[0]
if key["kty"] == "RSA":
    pub = rsa.RSAPublicNumbers(int.from_bytes(b64u(key["e"]), "big"),
                               int.from_bytes(b64u(key["n"]), "big")).public_key()
elif key["kty"] == "EC":
    crv = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1}[key["crv"]]
    pub = ec.EllipticCurvePublicNumbers(
        int.from_bytes(b64u(key["x"]), "big"),
        int.from_bytes(b64u(key["y"]), "big"), crv()).public_key()
else:
    raise SystemExit(f"Unsupported JWK kty: {key['kty']}")
print(pub.public_bytes(serialization.Encoding.PEM,
                       serialization.PublicFormat.SubjectPublicKeyInfo).decode())
PY
}

provision_client() {
  local client_id="$1" jwks_file="$2" pem
  echo "==> provisioning client '${client_id}' in realm '${KC_REALM}'"
  [ -s "$jwks_file" ] || { echo "::error::JWKS file empty/missing: $jwks_file" >&2; exit 1; }
  pem=$(convert_jwks_to_pem "$jwks_file")

  local existing
  existing=$(kcadm get clients -r "$KC_REALM" -q clientId="$client_id" 2>/dev/null | \
    $PYTHON_CMD -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if d else "")' 2>/dev/null || echo "")

  local body
  body=$(jq -n \
    --arg clientId "$client_id" \
    --arg pem "$pem" \
    '{clientId:$clientId, name:"OIDF FAPI 2.0 Conformance client", enabled:true, publicClient:false,
      standardFlowEnabled:true, serviceAccountsEnabled:false, directAccessGrantsEnabled:false,
      clientAuthenticatorType:"client-jwt",
      redirectUris:["https://www.certification.openid.net/test/a/*/callback",
                   "https://www.certification.openid.net/test/a/*/callback?dummy1=lorem&dummy2=ipsum"],
      attributes:{
        "jwt.credential.public.key":$pem,
        "token.endpoint.auth.signing.alg":"PS256",
        "dpop.bound.access.tokens":"true",
        "pkce.code.challenge.method":"S256",
        "require.pushed.authorization.requests":"true"}}')

  if [ -n "$existing" ]; then
    echo "    client exists (${existing}) - updating FAPI attributes"
    kcadm update "clients/$existing" -r "$KC_REALM" -b "$body"
  else
    kcadm create clients -r "$KC_REALM" -b "$body"
  fi
  echo "    client '${client_id}' configured (PS256 private_key_jwt + DPoP + PKCE S256 + PAR required)"
}

echo "==> authenticating kcadm against ${KC_ADMIN_URL}"
if [ -n "${KC_ADMIN_TOKEN:-}" ]; then
  kcadm config credentials --server "$KC_ADMIN_URL" --realm master --token "$KC_ADMIN_TOKEN" >/dev/null
else
  kcadm config credentials --server "$KC_ADMIN_URL" --realm master --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PASSWORD" >/dev/null
fi

provision_client "$CLIENT_ID" "$JWKS1"
provision_client "$CLIENT2_ID" "$JWKS2"

echo "==> conformance clients provisioned. Redirect URIs:"
echo "    https://www.certification.openid.net/test/a/*/callback"
echo "    https://www.certification.openid.net/test/a/*/callback?dummy1=lorem&dummy2=ipsum"
