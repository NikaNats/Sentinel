// Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
//
// keycloak-token-load.js - Scenario D3: direct Keycloak token issuance load.
//
// Bypasses Sentinel entirely and hammers the AS /token endpoint with the
// client_credentials grant to isolate Keycloak (PostgreSQL refresh-token
// writes, Infinispan session cache, GC pauses) from Sentinel API
// performance (docs/SRE_LOAD_TESTING_RUNBOOK.md §4.4).
//
// ENV:
//   KC_TOKEN_URL     full token endpoint
//                    https://keycloak.sentinel-prod.svc.cluster.local/realms/<realm>/protocol/openid-connect/token
//   KC_CLIENT_ID     load-testing confidential client (default sentinel-load-client)
//   KC_CLIENT_SECRET required
//   KC_RATE          target issuance RPS (default 2000)
//   KC_DURATION      (default 15m)
//
// Expected outcome: 200 + access_token at the configured rate; failures
// indicate Infinispan lock contention / DB pool exhaustion / GC pauses.
import http from 'k6/http';
import { check } from 'k6';

const TOKEN_URL = __ENV.KC_TOKEN_URL;
if (!TOKEN_URL) {
  throw new Error('[KC-LOAD] KC_TOKEN_URL is required');
}
const CLIENT_ID = __ENV.KC_CLIENT_ID || 'sentinel-load-client';
const CLIENT_SECRET = __ENV.KC_CLIENT_SECRET || '';
const RATE = Math.max(1, Number(__ENV.KC_RATE || 2000));
const DURATION = __ENV.KC_DURATION || '15m';

export const options = {
  scenarios: {
    token_issuance: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 100,
      maxVUs: 500,
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.001'],
    http_req_duration: ['p(99)<500'],
  },
};

export default function () {
  const res = http.post(
    TOKEN_URL,
    { grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET },
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: '5s' },
  );
  let hasToken = false;
  try {
    hasToken = !!JSON.parse(res.body).access_token;
  } catch {
    /* non-JSON error body */
  }
  check(res, {
    'token endpoint 200 with access_token': (r) => r.status === 200 && hasToken,
  });
}