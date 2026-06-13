import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import exec from 'k6/execution';

// --- Metrics & Telemetry ---
export const errorRate = new Rate('errors');
export const failClosedRate = new Rate('fail_closed_503');
export const authLatency = new Trend('auth_dpop_latency', true);

// --- High-Scale Engine Options ---
export const options = {
    discardResponseBodies: true,
    noConnectionReuse: false,
    scenarios: {
        avalanche_fake_nonces: {
            executor: 'constant-arrival-rate',
            rate: 100000,
            timeUnit: '1s',
            duration: '2m',
            preAllocatedVUs: 2000,
            maxVUs: 20000,
            exec: 'avalancheFakeNonces',
        },
        jti_replay_storm: {
            executor: 'constant-vus',
            vus: 10000,
            duration: '30s',
            exec: 'jtiReplayStorm',
        },
        cryptographic_cpu_exhaustion: {
            executor: 'constant-arrival-rate',
            rate: 5000,
            timeUnit: '1s',
            duration: '1m30s',
            preAllocatedVUs: 500,
            maxVUs: 3000,
            exec: 'cryptoCpuExhaustion',
        },
    },
    thresholds: {
        'auth_dpop_latency': ['p(99)<200'],
        'errors': ['rate<0.01'],
        'fail_closed_503': ['rate<0.001'],
    },
};

// --- Cryptographic Constants ---
const TARGET_URL = 'http://localhost:5260/api/v1/finance/transfer';
const PRE_COMPUTED_ACCESS_TOKEN = 'eyJhbGciOiJQUzI1NiI...';
const PRE_COMPUTED_DPOP_PROOF = 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0...';

// MEMORY OPTIMIZATION: Pre-allocate 50KB padding globally once. 
// Prevents generating 250MB/sec of garbage strings on the heap under 5,000 RPS load.
const LARGE_PADDING = 'x'.repeat(50000);

const BASE_HEADERS = {
    'Authorization': `DPoP ${PRE_COMPUTED_ACCESS_TOKEN}`,
    'Content-Type': 'application/json',
};

// --- Reusable Domain Logic ---
function buildHeaders(variant, uniqueId) {
    const headers = Object.assign({}, BASE_HEADERS, {
        'Idempotency-Key': `k6-stress-${uniqueId}-${variant}`
    });

    if (variant === 'replay_same_jti') {
        headers['DPoP'] = 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0... (same jti)';
    } else if (variant === 'large_jwt') {
        headers['DPoP'] = 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0... (large jwk)';
    } else {
        headers['DPoP'] = PRE_COMPUTED_DPOP_PROOF;
    }

    return headers;
}

// SOLID: Single Responsibility Principle (SRP) execution router
function executeScenario(variant, tag, buildPayload, expectedStatuses) {
    const uniqueId = `${exec.vu.idInTest}-${exec.scenario.iterationInTest}`;
    const headers = buildHeaders(variant, uniqueId);
    const payload = buildPayload(uniqueId);

    const res = http.post(TARGET_URL, payload, { headers: headers, tags: { name: tag } });

    authLatency.add(res.timings.duration);

    const ok = check(res, {
        [`status is ${expectedStatuses.join('/')}`]: (r) => expectedStatuses.includes(r.status),
    });

    errorRate.add(!ok || res.status >= 500);
    failClosedRate.add(res.status === 503);
}

// --- Entry Point Wrappers (KISS / DRY) ---
export function avalancheFakeNonces() {
    executeScenario(
        'fake_nonce',
        'Avalanche',
        (id) => `{"transactionId":"txn-${id}","amount":50.00,"currency":"USD","destinationAccount":"stress-test-acc"}`,
        [401, 429, 503]
    );
}

export function jtiReplayStorm() {
    executeScenario(
        'replay_same_jti',
        'Jti_Storm',
        (id) => `{"transactionId":"txn-replay-${id}","amount":1.00,"currency":"USD","destinationAccount":"stress-test-acc"}`,
        [401, 429, 503]
    );
}

export function cryptoCpuExhaustion() {
    executeScenario(
        'large_jwt',
        'Cpu_Exhaustion',
        (id) => `{"transactionId":"txn-cpu-${id}","amount":50.00,"currency":"USD","destinationAccount":"stress-test-acc","largePayload":"${LARGE_PADDING}"}`,
        [413, 401, 429, 503]
    );
}

// --- Lifecycle Hooks ---
export function setup() {
    return { startTime: Date.now() };
}

export function teardown(data) {
    const durationSec = (Date.now() - data.startTime) / 1000;
    console.log(`Load test completed successfully in ${durationSec.toFixed(2)}s`);
}
