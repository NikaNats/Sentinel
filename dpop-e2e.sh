#!/bin/sh
set -eu
cd /tmp
export NODE_TLS_REJECT_UNAUTHORIZED=0

URL="https://sentinel:8080/v1/profile"

echo "== MINT =="
node mint-dpop-pool.mjs --count 2 --out pool.json \
  --keycloak-url https://keycloak:8443 \
  --realm sentinel-dast \
  --client sentinel-dast-scanner \
  --client-secret 9zmnLb5H7wJBZhN9vMfvZCHY0NV95udF 2>&1 | grep -vi warning || true

TOKEN=$(node sign.mjs --pool pool.json --index 0 --url "$URL" --token-only)

req() {
  M="$1"
  A="$2"
  P="$3"
  U="$4"
  node --input-type=module -e '
    const [m, auth, proof, url] = process.argv.slice(2);
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

echo "== STEP A: Bearer-only downgrade (expect 401) =="
curl -sk -D h_a.txt -o b_a.txt -H "Authorization: DPoP $TOKEN" "$URL" || true
grep -E '^HTTP/' h_a.txt

echo "== STEP B: valid proof WITHOUT nonce =="
P1=$(sign_get)
req GET "DPoP $TOKEN" "$P1" "$URL"

NONCE=$(kubectl -n sentinel-test exec dpop-runner -- sh -c "NODE_TLS_REJECT_UNAUTHORIZED=0 curl -sk https://sentinel:8080/v1/profile -H 'Authorization: DPoP $(node sign.mjs --pool pool.json --index 0 --url '$URL' --method GET)' 2>/dev/null" | grep 'DPoP-Nonce' | head -1 | sed 's/.*: //' | tr -d '\r') || NONCE=""
echo "resolved nonce from challenge: ${NONCE:-<none-from-challenge>}"

if [ -z "$NONCE" ]; then
  echo "no nonce challenge; retrying with fresh proof (expect 200) =="
  P2=$(sign_get)
  req GET "DPoP $TOKEN" "$P2" "$URL"
else
  echo "== retrying WITH nonce (expect 200) =="
  P3=$(node sign.mjs --pool pool.json --index 0 --url "$URL" --method GET --nonce "$NONCE")
  req GET "DPoP $TOKEN" "$P3" "$URL"

  echo "== STEP C: replay same proof+jti (expect 401) =="
  P4="$P3"
  req GET "DPoP $TOKEN" "$P4" "$URL"
fi

echo "== E2E DANCE COMPLETED =="
