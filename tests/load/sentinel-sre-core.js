// Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
//
// sentinel-sre-core.js - shared SRE Load / Soak / Capacity suite core.
//
// Entry points (thin wrappers over this module):
//   sentinel-sre-suite.js     - stock k6 (webcrypto signing)
//   sentinel-sre-suite-xk6.js - xk6 build with the Go-native DPoP signer
//                               (tests/load/xk6-dpop; see Dockerfile.xk6)
//
// Corrections vs the 2026 Enterprise guide:
//   1. REAL ES256 DPoP proofs. The guide's HMAC-SHA256 "proof" with a
//      hardcoded symmetric demo key can never pass: Sentinel only accepts
//      ES256/PS256/EdDSA/ML-DSA (DpopProofValidator.cs:17) and requires
//      cnf.jkt == proof-key thumbprint (jkt_mismatch, DpopProofValidator.cs:254).
//      Each VU signs with a real P-256 key from the pool minted by
//      tests/scripts/mint-dpop-pool.mjs. k6/experimental/webcrypto ECDSA
//      emits IEEE P1363 raw r||s (the exact JWS ES256 signature format).
//   2. Nonce challenge loop. Sentinel returns DPoP-Nonce on challenges and
//      rotates it on success (Redis nonce store); VUs capture the header and
//      re-sign until accepted (bounded retries).
//   3. Authorization: DPoP <token> (Sentinel's scheme); the "DPoP" header
//      carries the proof. RAR: optional RFC 9396 Authorization-Details.
//
// Modes (TEST_MODE): soak | spike | capacity
// ENV: K6_POOL_FILE, TARGET_URL, TEST_MODE, SOAK_RPS, SOAK_DURATION,
//      K6_BEARER (dev fallback), K6_NONCE=0 disable challenge loop,
//      USE_RAR=1 attach Authorization-Details.
// NOTE: k6 v0.52 (the pinned runner in CI, Makefile and the SRE CRDs) does
// NOT expose a global `crypto` - webcrypto graduated to a global only in
// k6 v1.x. Import it explicitly for 0.52 compatibility.
import { crypto } from 'k6/experimental/webcrypto';
import encoding from 'k6/encoding';
import http from 'k6/http';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const BASE_URL = __ENV.TARGET_URL || 'https://sentinel-api.sentinel-prod.svc.cluster.local';
const TEST_MODE = __ENV.TEST_MODE || 'soak';
const POOL_FILE = __ENV.K6_POOL_FILE || '/pool/dpop-pool.json';
// Distributed runs: each k6-operator replica runs the SAME script; the rates
// declared here are the AGGREGATE targets, so every replica divides by
// K6_PARALLELISM (the guide's "10 runners x 2,000 RPS = 20,000 RPS" premise
// requires this - otherwise 10 replicas would sum to 200,000 RPS).
const PARALLELISM = Math.max(1, Number(__ENV.K6_PARALLELISM || 1));
const SOAK_RPS = Math.max(1, Number(__ENV.SOAK_RPS || 3500));
const SPIKE_MAX_RPS = Math.max(1, Number(__ENV.SPIKE_MAX_RPS || 20000));
const SPIKE_DURATION = __ENV.SPIKE_DURATION || '3m';
const CAPACITY_MAX_RPS = Math.max(1, Number(__ENV.CAPACITY_MAX_RPS || 15000));
const SOAK_DURATION = __ENV.SOAK_DURATION || '48h';
const USE_NONCE = __ENV.K6_NONCE !== '0';
const USE_RAR = __ENV.USE_RAR === '1';
const MAX_NONCE_RETRIES = 3;
const div = (n) => Math.max(1, Math.floor(n / PARALLELISM));

const TRANSFER_URL = `${BASE_URL}/api/v1/finance/transfer`;

// SRE telemetry
const dpopGenDuration = new Trend('sentinel_dpop_gen_duration_ms');
const socketErrors = new Counter('sentinel_socket_exhaustion_errors');
const rpsTracker = new Counter('sentinel_completed_requests');
const nonceChallenges = new Counter('sentinel_dpop_nonce_challenges');

// utf8 -> bytes shim (k6 v2.x no longer ships a global TextEncoder).
const encoder = {
  encode: (s) => new Uint8Array(encoding.b64decode(encoding.b64encode(s, 'rawurl'), 'rawurl')),
};

function b64url(value) {
  // string -> bytes, or byte array -> base64url (k6 rawurl)
  if (typeof value === 'string') return encoding.b64encode(value, 'rawurl');
  return encoding.b64encode(new Uint8Array(value), 'rawurl');
}

// ---- Signer selection ------------------------------------------------------
// Default: per-request webcrypto ES256 (works on stock k6).
// The xk6 entry (sentinel-sre-suite-xk6.js) overrides with the Go-native
// signer via setSigner() - orders of magnitude faster than JS crypto, which
// is the load generator bottleneck at ~2-3k proofs/sec/runner.
let signerOverride = null;

export function setSigner(fn) {
  signerOverride = fn;
}

// ---- DPoP pool (minted by tests/scripts/mint-dpop-pool.mjs) ----------------
let poolKeys = [];
try {
  // k6 open() resolves relative to the SCRIPT directory, so also accept the
  // bare filename (CI/make pass a path relative to the repo root).
  const candidates = [POOL_FILE, POOL_FILE.split(/[\\/]/).pop()];
  let raw = null;
  for (const cand of candidates) {
    try {
      raw = open(cand);
      break;
    } catch (e) {
      /* try next */
    }
  }
  if (raw === null) throw new Error('not found in script dir or repo root');
  const parsed = JSON.parse(raw);
  poolKeys = parsed.keys || [];
} catch (e) {
  throw new Error(`[SRE-SUITE] cannot read DPoP pool '${POOL_FILE}': ${e.message} - run tests/scripts/mint-dpop-pool.mjs first`);
}
if (poolKeys.length === 0) {
  throw new Error('[SRE-SUITE] DPoP pool is empty; run tests/scripts/mint-dpop-pool.mjs first');
}

// importKey is expensive; cache per VU (webcrypto path only).
const vuKeyCache = {};

// Shared with the chaos suite (tests/load/chaos-load-test.js): resolve the
// per-VU pool entry (P-256 key + Keycloak-issued cnf.jkt-bound token).
export function getPoolEntry(vu) {
  return poolKeys[vu % poolKeys.length];
}

async function keyFor(vu) {
  if (vuKeyCache[vu]) return vuKeyCache[vu];
  const entry = poolKeys[vu % poolKeys.length];
  const cryptoKey = await crypto.subtle.importKey('jwk', entry.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  vuKeyCache[vu] = { entry, cryptoKey };
  return vuKeyCache[vu];
}

async function signProof(entry, cryptoKey, method, url, nonce) {
  const t0 = Date.now();
  const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: { kty: 'EC', crv: entry.jwk.crv, x: entry.jwk.x, y: entry.jwk.y } };
  const payload = { jti: `${__VU}-${__ITER}-${Date.now()}`, htm: method, htu: url, iat: Math.floor(Date.now() / 1000) };
  if (nonce) payload.nonce = nonce;
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, cryptoKey, encoder.encode(signingInput));
  const proof = `${signingInput}.${b64url(sig)}`;
  dpopGenDuration.add(Date.now() - t0);
  return proof;
}

async function signProofFor(entry, method, url, nonce) {
  if (signerOverride) {
    const t0 = Date.now();
    const proof = signerOverride(method, url, JSON.stringify(entry.jwk), {
      nonce: nonce || '',
      iat: Math.floor(Date.now() / 1000),
      jti: `${__VU}-${__ITER}-${Date.now()}`,
    });
    dpopGenDuration.add(Date.now() - t0);
    return proof;
  }
  const { cryptoKey } = await keyFor(__VU);
  return signProof(entry, cryptoKey, method, url, nonce);
}

function requestHeaders(token, proof, nonce) {
  const headers = {
    Authorization: `DPoP ${token}`,
    DPoP: proof,
    'Content-Type': 'application/json',
  };
  if (USE_RAR) headers['Authorization-Details'] = JSON.stringify({ type: 'urn:sentinel:transfer', actions: ['execute'] });
  if (nonce) headers['DPoP-Nonce'] = nonce; // informational; the proof itself carries the nonce
  return headers;
}

async function doTransfer(token, nonce) {
  const entry = poolKeys[__VU % poolKeys.length];
  const proof = await signProofFor(entry, 'POST', TRANSFER_URL, nonce);
  const payload = JSON.stringify({
    transactionId: `txn-${__VU}-${__ITER}-${Date.now()}`,
    amount: 250.5,
    currency: 'USD',
    destinationAccount: 'acc-enterprise-999',
  });
  const res = http.post(TRANSFER_URL, payload, { headers: requestHeaders(token, proof, nonce), timeout: '2s' });
  return { res, proof };
}

export default async function () {
  const entry = poolKeys[__VU % poolKeys.length];
  const token = entry.token || __ENV.K6_BEARER || '';
  if (!token) {
    socketErrors.add(1);
    return;
  }

  let { res } = await doTransfer(token, null);
  let attempts = 1;
  while (USE_NONCE && attempts < MAX_NONCE_RETRIES && (res.status === 401 || res.status === 400)) {
    const nonceHeader = res.headers['dpop-nonce'];
    if (!nonceHeader) break;
    nonceChallenges.add(1);
    const next = await doTransfer(token, nonceHeader);
    res = next.res;
    attempts += 1;
  }

  rpsTracker.add(1);

  if (res.status === 200 || res.status === 503) {
    // expected resilient / fail-closed responses
  } else if (res.status === 401 || res.status === 400) {
    socketErrors.add(1); // persistent auth rejection from a supposedly valid pool
  } else if (res.error_code === 1000 || res.error_code === 1050 || res.status === 0) {
    socketErrors.add(1);
  }

  check(res, {
    'status is 200 or 503 (resilient)': (r) => r.status === 200 || r.status === 503,
    'no server error (5xx)': (r) => r.status < 500,
    'latency < 100ms': (r) => r.timings.duration < 100,
  });
}

function getScenarios() {
  if (TEST_MODE === 'spike') {
    return {
      spike_scenario: {
        executor: 'ramping-arrival-rate',
        startRate: 100,
        timeUnit: '1s',
        preAllocatedVUs: 1000,
        maxVUs: 10000,
        stages: [
          { duration: '10s', target: div(500) },
          { duration: '3s', target: div(SPIKE_MAX_RPS) },
          { duration: SPIKE_DURATION, target: div(SPIKE_MAX_RPS) },
          { duration: '10s', target: div(500) },
        ],
      },
    };
  }
  if (TEST_MODE === 'capacity') {
    return {
      capacity_scenario: {
        executor: 'ramping-arrival-rate',
        startRate: 500,
        timeUnit: '1s',
        preAllocatedVUs: 1000,
        maxVUs: 10000,
        stages: [
          { duration: '2m', target: div(2000) },
          { duration: '2m', target: div(4000) },
          { duration: '2m', target: div(6000) },
          { duration: '2m', target: div(8000) },
          { duration: '2m', target: div(10000) },
          { duration: '2m', target: div(12000) },
          { duration: '2m', target: div(CAPACITY_MAX_RPS) },
        ],
      },
    };
  }
  return {
    soak_scenario: {
      executor: 'constant-arrival-rate',
      rate: div(SOAK_RPS),
      timeUnit: '1s',
      duration: SOAK_DURATION,
      preAllocatedVUs: Math.min(div(SOAK_RPS), 2000),
      maxVUs: Math.max(div(SOAK_RPS) * 2, 2000),
    },
  };
}

export const options = {
  scenarios: getScenarios(),
  insecureSkipTLSVerify: __ENV.K6_INSECURE === '1', // KinD/dev self-signed certs (never in prod)
  thresholds: {
    'http_req_failed': ['rate<0.001'],
    'sentinel_socket_exhaustion_errors': ['count==0'],
    'http_req_duration{scenario:soak_scenario}': ['p(99)<35'],
    'http_req_duration{scenario:spike_scenario}': ['p(99)<100'],
  },
};