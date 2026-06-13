import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import exec from 'k6/execution';

// Metrics
export const errorRate = new Rate('errors');
export const failClosedRate = new Rate('fail_closed_503');
export const authLatency = new Trend('auth_dpop_latency', true);

// Configuration & Thresholds
export const options = {
    discardResponseBodies: true, // Discard bodies to prevent k6 RAM exhaustion at 10k RPS
    noConnectionReuse: false,    // Reuse connections to prevent Windows port starvation
    scenarios: {
        avalanche_fake_nonces: {
            executor: 'constant-arrival-rate',
            rate: 10000,
            timeUnit: '1s',
            duration: '10s',
            preAllocatedVUs: 500,
            maxVUs: 1500,
            exec: 'avalancheFakeNonces',
        },
    },
    thresholds: {
        'auth_dpop_latency': ['p(99)<200'],
        'errors': ['rate<0.01'],
        'fail_closed_503': ['rate<0.001'],
    },
};

// Constants
const TARGET_URL = 'http://localhost:5260/api/v1/finance/transfer';

const PRE_COMPUTED_ACCESS_TOKEN = 'eyJhbGciOiJQUzI1NiI...';
const PRE_COMPUTED_DPOP_PROOF = 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0...';

const BASE_HEADERS = {
    'Authorization': `DPoP ${PRE_COMPUTED_ACCESS_TOKEN}`,
    'DPoP': PRE_COMPUTED_DPOP_PROOF,
    'Content-Type': 'application/json',
};

// Execution Payload
export function avalancheFakeNonces() {
    const uniqueId = `${exec.vu.idInTest}-${exec.scenario.iterationInTest}`;

    // Shallow clone headers to inject the unique Idempotency-Key
    const headers = Object.assign({}, BASE_HEADERS, {
        'Idempotency-Key': `k6-stress-${uniqueId}`
    });

    // Fast template literal payload concatenation
    const payload = `{"transactionId":"txn-${uniqueId}","amount":50.00,"currency":"USD","destinationAccount":"stress-test-acc"}`;

    const res = http.post(TARGET_URL, payload, {
        headers: headers,
        tags: { name: 'Adversarial_Transfer' }
    });

    // Add native Go-measured response latency
    authLatency.add(res.timings.duration);

    const ok = check(res, {
        'status is 401/429/503 (fail-closed)': (r) => r.status === 401 || r.status === 429 || r.status === 503,
        'status is NOT 200 (secure)': (r) => r.status !== 200,
    });

    errorRate.add(!ok || res.status >= 500);


    if (res.status === 503) {
        failClosedRate.add(1);
    }
}
