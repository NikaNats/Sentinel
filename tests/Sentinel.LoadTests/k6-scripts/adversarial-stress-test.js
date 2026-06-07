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
            rate: 100000,
            timeUnit: '1s',
            duration: '2m',
            preAllocatedVUs: 2000,
            maxVUs: 20000,
            exec: 'avalancheFakeNonces',
            startTime: '0s',
        },
        jti_replay_storm: {
            executor: 'constant-vus',
            vus: 10000,
            duration: '30s',
            exec: 'jtiReplayStorm',
            startTime: '0s',
        },
        cryptographic_cpu_exhaustion: {
            executor: 'constant-arrival-rate',
            rate: 5000,
            timeUnit: '1s',
            duration: '1m30s',
            preAllocatedVUs: 500,
            maxVUs: 3000,
            exec: 'cryptoCpuExhaustion',
            startTime: '0s',
        },
    },
    thresholds: {
        'auth_dpop_latency': ['p(99)<50'],
        'errors': ['rate<0.01'],
        'fail_closed_503': ['rate<0.001'],
    },
};

const TARGET_URL = 'http://localhost:5000/api/v1/finance/transfer';

const PRE_COMPUTED_ACCESS_TOKEN = 'eyJhbGciOiJQUzI1NiI...';
const PRE_COMPUTED_DPOP_PROOF = 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0...';

function buildHeaders(variant) {
    const headers = {
        'Authorization': `DPoP ${PRE_COMPUTED_ACCESS_TOKEN}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': `k6-stress-${__ITER}-${__VU}-${variant}`,
    };

    if (variant === 'replay_same_jti') {
        headers['DPoP'] = 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0... (same jti)';
    } else if (variant === 'large_jwt') {
        headers['DPoP'] = 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0... (large jwk)';
    } else {
        headers['DPoP'] = PRE_COMPUTED_DPOP_PROOF;
    }

    return headers;
}

export function avalancheFakeNonces() {
    let headers = buildHeaders('fake_nonce');
    let payload = JSON.stringify({
        transactionId: `txn-${__ITER}`,
        amount: 50.00,
        currency: 'USD',
        destinationAccount: 'stress-test-acc',
    });

    // ✅ FIX: დროის ათვლა იწყება რექვესთამდე
    const start = Date.now();
    let res = http.post(TARGET_URL, payload, { headers: headers });
    authLatency.add(Date.now() - start);

    let ok = check(res, {
        'status is 401/429/503': (r) => [401, 429, 503].includes(r.status),
    });

    errorRate.add(!ok || res.status >= 500);
    failClosedRate.add(res.status === 503);
}

export function jtiReplayStorm() {
    let headers = buildHeaders('replay_same_jti');
    let payload = JSON.stringify({
        transactionId: `txn-replay-${__VU}-${__ITER}`,
        amount: 1.00,
        currency: 'USD',
        destinationAccount: 'stress-test-acc',
    });

    const start = Date.now();
    let res = http.post(TARGET_URL, payload, { headers: headers });
    authLatency.add(Date.now() - start);

    let ok = check(res, {
        'status is 401/429/503': (r) => [401, 429, 503].includes(r.status),
    });

    errorRate.add(!ok || res.status >= 500);
    failClosedRate.add(res.status === 503);
}

export function cryptoCpuExhaustion() {
    let headers = buildHeaders('large_jwt');
    let payload = JSON.stringify({
        transactionId: `txn-cpu-${__ITER}`,
        amount: 50.00,
        currency: 'USD',
        destinationAccount: 'stress-test-acc',
        largePayload: 'x'.repeat(50000), // 50 KB
    });

    const start = Date.now();
    let res = http.post(TARGET_URL, payload, { headers: headers });
    authLatency.add(Date.now() - start);

    let ok = check(res, {
        // ✅ FIX: Kestrel მყისიერად აბრუნებს 413-ს, რაც წარმატებული დაცვაა და არა შეცდომა
        'status is 413/401/429/503': (r) => [413, 401, 429, 503].includes(r.status),
    });

    errorRate.add(!ok || res.status >= 500);
    failClosedRate.add(res.status === 503);
}

export function setup() {
    return { startTime: Date.now() };
}

export function teardown(data) {
    const durationSec = (Date.now() - data.startTime) / 1000;
    console.log(`Load test completed in ${durationSec.toFixed(2)}s`);
}
