import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend } from 'k6/metrics';

export const errorRate = new Rate('errors');
export const failClosedRate = new Rate('fail_closed_503');
export const authLatency = new Trend('auth_dpop_latency', true);

export const options = {
    scenarios: {
        avalanche_fake_nonces: {
            executor: 'constant-arrival-rate',
            rate: 10000, // Lowered to 10K for local Windows testing
            timeUnit: '1s',
            duration: '10s',
            preAllocatedVUs: 100,
            maxVUs: 500,
            exec: 'avalancheFakeNonces',
            startTime: '0s',
        },
    },
    thresholds: {
        'auth_dpop_latency': ['p(99)<200'],
        'errors': ['rate<0.01'],
        'fail_closed_503': ['rate<0.001'],
    },
};

const TARGET_URL = 'http://localhost:5000/api/v1/finance/transfer';

const PRE_COMPUTED_ACCESS_TOKEN = 'eyJhbGciOiJQUzI1NiI...';
const PRE_COMPUTED_DPOP_PROOF = 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0...';

export function avalancheFakeNonces() {
    let headers = {
        'Authorization': `DPoP ${PRE_COMPUTED_ACCESS_TOKEN}`,
        'DPoP': PRE_COMPUTED_DPOP_PROOF,
        'Content-Type': 'application/json',
        'Idempotency-Key': `k6-stress-${__ITER}-${__VU}`,
    };

    let payload = JSON.stringify({
        transactionId: `txn-${__ITER}`,
        amount: 50.00,
        currency: 'USD',
        destinationAccount: 'stress-test-acc',
    });

    const start = Date.now();
    let res = http.post(TARGET_URL, payload, { headers: headers });
    authLatency.add(Date.now() - start);

    let ok = check(res, {
        'status is 401/429/503 (fail-closed)': (r) => [401, 429, 503].includes(r.status),
        'status is NOT 200': (r) => r.status !== 200,
    });

    errorRate.add(!ok || res.status >= 500);
    failClosedRate.add(res.status === 503);
}

export default function () {
    avalancheFakeNonces();
}
