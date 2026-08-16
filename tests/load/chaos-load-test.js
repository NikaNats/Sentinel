// Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
//
// Chaos load generation for the Sentinel Fail-Closed Distributed Resilience Gate.
//
// Authenticates with REAL RFC 9449 DPoP: each VU signs a fresh proof per
// request with its own P-256 key from the pool minted by
// tests/scripts/mint-dpop-pool.mjs --keycloak-url (tokens carry cnf.jkt and
// the gate's Keycloak client binds them, so Sentinel's DpopProofValidator
// accepts the proof-key thumbprint instead of rejecting with jkt_mismatch).
// The signing machinery is shared with the SRE suite (sentinel-sre-core.js).
//
// Usage (all values overridable via environment):
//   K6_POOL_FILE  DPoP pool JSON (required; keys[].token carries cnf.jkt)
//   K6_LOAD_URL   base URL,  default https://sentinel-api.sentinel-prod.svc.cluster.local
//   K6_RATE       requests/sec,  default 5000
//   K6_DURATION   scenario duration, default 60s
//   K6_SCENARIO   chaos scenario tag: redis-kill | pg-partition | dns-latency | cascade
//   K6_NONCE=0    disable the DPoP-Nonce challenge loop (default enabled)
//   K6_HEALTH     probe /healthz additionally, validates 200 survives (default true)
//
// Success thresholds enforced by k6 itself:
//   - zero HTTP 500 across the whole run (the CANNOT-COMPROMISE gate)
//   - the per-status breakdown is exported (--summary-export) so that
//     tests/scripts/validate-fail-closed.sh can assert the scenario invariants
//     (e.g. 503 mandatory during redis-kill, 0 x 200 during pg-partition).
//
// Run:  k6 run --summary-export tests/load/chaos-summary.json tests/load/chaos-load-test.js
import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { getPoolEntry, signProofFor } from './sentinel-sre-core.js';

const BASE_URL = __ENV.K6_LOAD_URL || 'https://sentinel-api.sentinel-prod.svc.cluster.local';
const RATE = Number(__ENV.K6_RATE || 5000);
const DURATION = __ENV.K6_DURATION || '60s';
const SCENARIO = __ENV.K6_SCENARIO || 'unknown';
const USE_NONCE = __ENV.K6_NONCE !== '0';
const MAX_NONCE_RETRIES = 3;
const WITH_HEALTH = (__ENV.K6_HEALTH || 'true') === 'true';

const serverErrors = new Counter('sentinel_http_server_500');
const failClosed503 = new Counter('sentinel_http_fail_closed_503');
const authErrors401 = new Counter('sentinel_http_auth_401');
const successes200 = new Counter('sentinel_http_success_200');

export const options = {
  scenarios: {
    constant_request_rate: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: Math.min(RATE, 1000),
      maxVUs: 5000,
    },
  },
  insecureSkipTLSVerify: true, // KinD gate: API cert is signed by the repo CA, not a public root
  thresholds: {
    // The unbreakable canary: not a single 500 through any chaos window.
    sentinel_http_server_500: [{ threshold: 'count == 0', abortOnFail: true }],
  },
};

async function doTransfer(entry, token, nonce) {
  const proof = await signProofFor(entry, 'POST', `${BASE_URL}/api/v1/finance/transfer`, nonce);
  const params = {
    headers: {
      'Authorization': `DPoP ${token}`,
      'DPoP': proof,
      'Idempotency-Key': `idemp-${__VU}-${__ITER}`,
      'Content-Type': 'application/json',
    },
    tags: { chaos: SCENARIO, vu: __VU, iter: __ITER },
    timeout: '2s',
  };
  if (nonce) params.headers['DPoP-Nonce'] = nonce;

  const res = http.post(
    `${BASE_URL}/api/v1/finance/transfer`,
    JSON.stringify({
      transactionId: `transfer-${__VU}-${__ITER}`,
      amount: 100,
      currency: 'USD',
      destinationAccount: 'acc-123',
    }),
    params,
  );
  return { res, proof };
}

export default async function () {
  // Per-VU pool entry: P-256 key + Keycloak-issued cnf.jkt-bound token
  // (minted by mint-dpop-pool.mjs --keycloak-url; Sentinel rejects any
  // proof whose key thumbprint does not match the token's cnf.jkt).
  const entry = getPoolEntry(__VU);
  const token = entry.token || '';
  let { res } = await doTransfer(entry, token, null);

  let attempts = 1;
  while (USE_NONCE && attempts < MAX_NONCE_RETRIES && (res.status === 401 || res.status === 400)) {
    const nonceHeader = res.headers['dpop-nonce'];
    if (!nonceHeader) break;
    const next = await doTransfer(entry, token, nonceHeader);
    res = next.res;
    attempts += 1;
  }

  if (res.status === 200) successes200.add(1);
  if (res.status === 401) authErrors401.add(1);
  if (res.status === 503) failClosed503.add(1);
  if (res.status === 500) serverErrors.add(1);

  check(res, {
    'is 200 or 503 or 401 (Resilient / Fail-Closed)':
      (r) => r.status === 200 || r.status === 503 || r.status === 401,
    'is NOT 500 (No Unhandled Crashes)': (r) => r.status !== 500,
  });

  if (WITH_HEALTH && __ITER % Math.max(1, Math.floor(RATE / 100)) === 0) {
    const health = http.get(`${BASE_URL}/healthz`, { timeout: '2s' });
    check(health, { 'healthz is 200': (r) => r.status === 200 });
  }
}