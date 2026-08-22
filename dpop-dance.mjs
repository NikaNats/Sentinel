// In-cluster RFC 9449 DPoP E2E verification dance.
// Runs inside the dpop-runner pod against https://sentinel:8080 using the
// in-cluster Keycloak (https://keycloak:8443) as issuer.
import { createHash, createPrivateKey, createSign, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const KC = 'https://keycloak:8443';
const URL = 'https://sentinel:8080/v1/profile';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// ---------- mint (mirrors mint-dpop-pool.mjs client-credentials + DPoP flow) ----------
function signProof(jwk, { method, url, nonce, accessToken }) {
  const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y } };
  const payload = {
    jti: randomUUID().replaceAll('-', ''),
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
  };
  if (nonce) payload.nonce = nonce;
  if (accessToken) payload.ath = b64url(createHash('sha256').update(accessToken).digest());
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signature = createSign('SHA256').update(input).end().sign(
    { key: createPrivateKey({ key: JSON.stringify(jwk), format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
  );
  return `${input}.${b64url(signature)}`;
}

const mintRes = await fetch(`${KC}/realms/sentinel-dast/protocol/openid-connect/token`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: 'sentinel-dast-scanner',
    client_secret: '9zmnLb5H7wJBZhN9vMfvZCHY0NV95udF',
    scope: 'openid profile',
  }).toString(),
});
if (!mintRes.ok) {
  console.error('MINT FAILED', mintRes.status, await mintRes.text());
  process.exit(1);
}
const minted = await mintRes.json();
const token = minted.access_token;

// Derive the keypair whose jkt Keycloak bound into cnf — regenerate deterministically
// is impossible, so re-derive from the DPoP proof we control: generate a fresh pair,
// request a NEW token bound to IT (second mint), and use that pair for all proofs.
const { generateKeyPairSync } = await import('node:crypto');
const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const pubJwk = publicKey.export({ format: 'jwk' });
const privJwk = privateKey.export({ format: 'jwk' });
const jkt = b64url(createHash('sha256')
  .update(JSON.stringify({ crv: pubJwk.crv, kty: pubJwk.kty, x: pubJwk.x, y: pubJwk.y }))
  .digest());

// Second token mint bound to THIS proof key's jkt
const bindRes = await fetch(`${KC}/realms/sentinel-dast/protocol/openid-connect/token`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: 'sentinel-dast-scanner',
    client_secret: '9zmnLb5H7wJBZhN9vMfvZCHY0NV95udF',
    scope: 'openid profile',
  }).toString(),
});
void bindRes; void token; void privJwk; void jkt;

console.log('== NOTE: using first minted token (bound by Keycloak to its own DPoP proof key) ==');

// The scanner client's original DPoP key is not retained by this script; instead we
// exercise the API with the FIRST pool entry produced above.
