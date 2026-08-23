#!/usr/bin/env bash
set -euo pipefail
export NODE_TLS_REJECT_UNAUTHORIZED=0

# Use port 5260 for docker-compose (or 8080 for Kubernetes port-forward)
URL="http://localhost:5260/v1/profile"
KEYCLOAK_URL="https://localhost:8443"
POOL="${TEMP:-/tmp}/local-dpop-pool.json"

echo "== [1/3] Provisioning sentinel-gate client + Minting DPoP-bound Token =="

# First, provision the sentinel-gate client like validate-observability.sh does
ADMIN_TOKEN=$(curl -ksf -X POST \
  "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password&client_id=admin-cli&username=admin&password=admin' \
  | node -p "JSON.parse(require('fs').readFileSync(0,'utf8')).access_token")

GATE_CLIENT_ID=$(curl -ksf "$KEYCLOAK_URL/admin/realms/sentinel/clients?clientId=sentinel-gate" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | node -p "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); d.length?d[0].id:''")

CLIENT_JSON='{"clientId":"sentinel-gate","name":"Sentinel Gate Client","enabled":true,"publicClient":false,"secret":"gate-client-secret","clientAuthenticatorType":"client-secret","serviceAccountsEnabled":true,"standardFlowEnabled":false,"directAccessGrantsEnabled":false,"attributes":{"access.token.signed.response.alg":"PS256","access.token.lifespan":"300","dpop.bound.access.tokens":"true"},"defaultClientScopes":["roles","profile","email"],"protocolMappers":[{"name":"sentinel-api-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.custom.audience":"sentinel-api","access.token.claim":"true","id.token.claim":"false"}},{"name":"acr-gate","protocol":"openid-connect","protocolMapper":"oidc-hardcoded-claim-mapper","config":{"claim.name":"acr","claim.value":"acr2","jsonType":"String","access.token.claim":"true","id.token.claim":"false"}}]}'

if [ -z "$GATE_CLIENT_ID" ]; then
  curl -ksf -X POST "$KEYCLOAK_URL/admin/realms/sentinel/clients" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    -d "$CLIENT_JSON" >/dev/null
  GATE_CLIENT_ID=$(curl -ksf "$KEYCLOAK_URL/admin/realms/sentinel/clients?clientId=sentinel-gate" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    | node -p "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); d.length?d[0].id:''")
  echo "Created sentinel-gate client (id=$GATE_CLIENT_ID)"
else
  echo "sentinel-gate client exists (id=$GATE_CLIENT_ID)"
fi

echo "== [2/3] Minting DPoP-bound Token via Keycloak =="
node tests/scripts/mint-dpop-pool.mjs \
  --count 1 \
  --out "$POOL" \
  --keycloak-url "$KEYCLOAK_URL" \
  --realm sentinel --client sentinel-gate \
  --client-secret gate-client-secret

TOKEN=$(node tests/scripts/sign-dpop-proof.mjs --pool "$POOL" --index 0 --url "$URL" --token-only)
echo "Token acquired: ${TOKEN:0:30}..."

echo "== [3/3] Step 1: Initial Request (Expect 401 + DPoP-Nonce Challenge) =="
INITIAL_PROOF=$(node tests/scripts/sign-dpop-proof.mjs --pool "$POOL" --index 0 --url "$URL" --method GET)

curl -k -s -D /tmp/h1.txt -o /tmp/b1.txt -X GET "$URL" \
  -H "Authorization: DPoP $TOKEN" \
  -H "DPoP: $INITIAL_PROOF"

grep -E "HTTP/|DPoP-Nonce" /tmp/h1.txt | sed 's/^/   /'

NONCE=$(awk 'tolower($0) ~ /^dpop-nonce:/ {sub(/\r$/,"",$2); print $2}' /tmp/h1.txt | tail -1)
echo "Resolved Server Nonce: ${NONCE:-<none>}"

if [ -n "$NONCE" ]; then
  echo "== [4/4] Step 2: Retry with Server Nonce (Expect 200 OK) =="
  BOUND_PROOF=$(node tests/scripts/sign-dpop-proof.mjs --pool "$POOL" --index 0 --url "$URL" --method GET --nonce "$NONCE")

  curl -k -i -X GET "$URL" \
    -H "Authorization: DPoP $TOKEN" \
    -H "DPoP: $BOUND_PROOF"
fi