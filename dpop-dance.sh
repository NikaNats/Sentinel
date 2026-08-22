#!/bin/sh
# In-cluster RFC 9449 DPoP E2E dance.
# Runs inside dpop-runner against https://sentinel:8080 with issuer-aligned
# tokens minted from https://keycloak:8443 (sentinel-dast realm).
set -eu
cd /tmp
export NODE_TLS_REJECT_UNAUTHORIZED=0

URL="https://sentinel:8080/v1/profile"

echo "== MINT: client_credentials + DPoP-bound tokens =="
node mint-dpop-pool.mjs --count 2 --out pool.json \
  --keycloak-url https://keycloak:8443 \
  --realm sentinel-dast \
  --client sentinel-dast-scanner \
  --client-secret 9zmnLb5H7wJBZhN9vMfvZCHY0NV95udF 2>&1 | grep -vi warning || true

TOKEN=$(node sign.mjs --pool pool.json --index 0 --url "$URL" --token-only)

# HTTP helper: prints CODE, any NONCE= header value, and body prefix.
req() {
  M="$1"
  A="$2"
  P="$3"
  U="$4"
  node --input-type=module -e '
    const [m, auth, proof, url] = process.argv.slice(1);
    const headers = { authorization: auth };
    if (proof) headers.dpop = proof;
    const res = await fetch(url, { method: m, headers });
    console.log("CODE=" + res.status);
    for (const [h, v] of res.headers)
      if (/^dpop-nonce$/i.test(h)) console.log("NONCE=" + v);
    console.log((await res.text()).slice(0, 200));
  ' "$M" "$A" "$P" "$U"
}

sign_get() {
  if [ $# -gt 0 ]; then
    node sign.mjs --pool pool.json --index 0 --url "$URL" --method GET --nonce "$1"
  else
    node sign.mjs --pool pool.json --index 0 --url "$URL" --method GET
  fi
}

echo "== STEP 1: initial request WITHOUT nonce =="
P1=$(sign_get)
RESP=$(req GET "DPoP $TOKEN" "$P1" "$URL")
echo "$RESP"

NONCE=$(printf '%s\n' "$RESP" | sed -n 's/^NONCE=//p' | tail -1)

if [ -n "$NONCE" ]; then
  echo "== STEP 2: retry WITH server-issued nonce (expect CODE=200) =="
  P2=$(sign_get "$NONCE")
  RESP2=$(req GET "DPoP $TOKEN" "$P2" "$URL")
  echo "$RESP2"
else
  echo "== STEP 2 skipped: no nonce challenge in step 1 =="
fi

echo "== STEP 3: replay of last accepted proof (expect CODE=401, jti consumed) =="
LAST_PROOF=${P2:-$P1}
req GET "DPoP $TOKEN" "$LAST_PROOF" "$URL"
