# SRE Load Testing Runbook (Production-Scale)

> **Document ID**: DOC-0019
> **Status**: ACTIVE
> **Constitution Ref**: §VI (Observability), §VIII (Quality Gates), 99.99% availability mandate
> **Governs**: `infra/k8s/sre/` CRDs, `tests/load/sentinel-sre-suite*.js`, `tests/load/xk6-dpop/`,
> `tests/load/keycloak-token-load.js`, `.github/workflows/sre-load-gate.yml`,
> `.github/workflows/sre-distributed-gate.yml`, `infra/monitoring/sre-alerts.yaml`,
> `tests/scripts/validate-sre-soak.sh`
> **Baseline**: .NET 10.0 (AOT) · Keycloak 26.6.4 · Kubernetes · FAPI 2.0

## 1. Scope & Mandate

Sentinel must demonstrate — not assert — the Constitution's 99.99% availability
mandate under production-scale load: a 20,000 RPS spike, a 48-hour 3,500 RPS
soak, a capacity breakpoint sweep, and infrastructure cascade failures, all
while proving fail-closed semantics (Redis dead ⇒ 503, never fail-open).

This runbook is the operational companion to the load-testing architecture.
It supersedes local-only reasoning: the single-node k6 that validates in CI is
a **smoke**; the **authoritative** runs are the distributed k6-operator
workloads in `infra/k8s/sre/`.

## 2. Plan-Audit (What Was Already True vs New)

| Claim | Verdict | Evidence / Action |
|---|---|---|
| "sre-load-gate.yml validates fictional metric names" | **False (already corrected)** | Gate, validator and alerts query the REAL OTel-derived names (`auth_dpop_failures_total`, `auth_redis_degraded_mode_activations_total`, `auth_token_validation_duration_seconds_bucket`); the fictional `sentinel_redis_connection_failed_total` was replaced in a prior session |
| "cannot pre-generate a static DPoP proof pool" | **True, already handled** | Pool = P-256 **keys**; proofs are signed per request with fresh `iat` + server `nonce` (`sentinel-sre-core.js`) |
| "k6 JS signing bottlenecks the generator" | **True** | Webcrypto caps a runner at ~2-3k proofs/sec; **fixed** with the Go-native `xk6-dpop` signer (`tests/load/xk6-dpop/`, `Dockerfile.xk6`) |
| Distributed k6-operator topology | **Partially existed** | 3 CRDs existed (`infra/k8s/sre/`) but ran stock k6; now pinned to the xk6 runner image + xk6 suite entry |
| "p99 drift / memory slope / socket metrics" | True | All real and enforced by `sre-alerts.yaml` + `validate-sre-soak.sh` |
| Latent bug in the suite | **Found & fixed** | The original suite could not execute on the pinned k6 v0.52: (a) optional-catch-binding syntax error, (b) `crypto` global does not exist in v0.52 (webcrypto is a v1.x global). Both fixed in the core refactor; verified on stock k6 0.52 and the xk6 build |
| `make chaos-up` exists | True | KinD + Chaos Mesh + Sentinel stack; reused by the distributed gate |

## 3. Distributed Load Generation Architecture

### 3.1 Topology

- **Grafana k6-operator** in a dedicated `load-testing` namespace (or the
  `sentinel-prod` namespace, matching the existing CRDs).
- Runner pods in the **same AZ as the Sentinel ingress** (no cross-AZ latency
  jitter) but on **separate node pools** (no CPU starvation of the API).
- Per-runner rate = aggregate ÷ parallelism: the suite divides by
  `K6_PARALLELISM`, so 10 runners × 2,000 RPS = 20,000 RPS aggregate
  (not 200,000).

### 3.2 HTTP/2 & Socket Exhaustion

- k6 negotiates HTTP/2 (ALPN) automatically over TLS; verify the ingress/API
  terminates TLS with `h2` (`curl -sI --http2` or `openssl s_client -alpn h2`).
  HTTP/2 multiplexing is what keeps ephemeral-port pressure low at 20k RPS.
- Node tuning for the runner pool (kubelet-managed nodes; apply via a
  DaemonSet or AMI/VM template):

  ```bash
  sysctl -w net.ipv4.ip_local_port_range="1024 65535"
  sysctl -w net.ipv4.tcp_tw_reuse=1
  sysctl -w net.core.somaxconn=65535
  ```

- `sentinel_socket_exhaustion_errors` (k6 counter) and
  `node_sockstat_TCP_tw` (node-exporter, alert > 20,000) are the tripwires.

### 3.3 The DPoP Cryptographic Bottleneck (`xk6-dpop`)

RFC 9449 forbids static proofs (fresh `iat` ±60s, server-issued `nonce`).
The xk6 extension (`tests/load/xk6-dpop/`) signs ES256 in Go
(`crypto/ecdsa`), sustaining the per-runner target; the JS webcrypto fallback
remains for stock-k6 runs. Built via `tests/load/Dockerfile.xk6`.

```bash
tests/scripts/build-xk6-dpop.sh                      # -> sentinel-k6-dpop:local
kind load docker-image sentinel-k6-dpop:local --name <cluster>
```

The suite selects the signer by entry point:
- `sentinel-sre-suite.js` → stock k6 (webcrypto; CI gate, `make sre-run`)
- `sentinel-sre-suite-xk6.js` → xk6 runner (CRDs, distributed gate)

## 4. Scenario Matrix

| Scenario | Artifact | Profile | Pass criteria |
|---|---|---|---|
| **A. Soak** (48h) | `crd-soak-48h.yaml` + `validate-sre-soak.sh` | 3,500 RPS × 48h | zero OOMKills, zero 503s, memory slope ≤ 1KB/s (12h deriv), p99 drift < 5ms, p99 ≤ 50ms |
| **B. Spike** (0→20k) | `crd-spike-20k.yaml` | 0→20k RPS in 3s, hold 3m | p99 < 500ms during ramp, error rate < 0.1%, `auth_redis_degraded_mode_activations_total` = 0, no pod crash |
| **C. Capacity** (step) | `crd-capacity.yaml` | +1,000 RPS / 2m until p99 > 200ms or error > 1% | capacity matrix output (§9) |
| **D1. Redis latency** | chaos-mesh network latency / Toxiproxy 50ms | `RedisJtiReplayCache` → `ReplayCacheUnavailableException` → **503** | fail-closed, no fail-open |
| **D2. Redis kill** | `make chaos-gate CHAOS_SCENARIO=redis-kill` | kill Redis at 5,000 RPS | `HybridSessionBlacklistCache` → PostgreSQL fallback; 503s, no data corruption, `auth_redis_degraded_mode_activations_total` > 0 (expected) |
| **D3. Keycloak /token** | `tests/load/keycloak-token-load.js` | 2,000 RPS client_credentials × 15m | p99 < 500ms, error rate < 0.1% |

D1/D2 reuse the chaos-gate machinery (`Makefile` `chaos-up`/`chaos-inject`/
`chaos-load`/`chaos-validate`; `tests/scripts/validate-fail-closed.sh`).

### 4.1 Scenario A — metrics to watch

- `container_memory_working_set_bytes{container="sentinel-api"}` — must be flat
  (alert: slope > 0 over 6h and predicted limit breach; `sre-alerts.yaml` #1).
- `.NET` Gen 2 heap via `/metrics` if the AOT runtime exposes GC stats.
- Npgsql pool: enable `NpgsqlDataSource` metrics (`npgsql_pool_active/idle`)
  on the deployment if pool-fragmentation evidence is required (not yet
  emitted — see §7.3).

### 4.2 Scenario B — thread starvation

- Trigger: Kestrel thread pool queue growth on the 3s ramp.
- `L1AntiFloodCache` (3s TTL, `Sentinel.AspNetCore/Stores/`) absorbs the
  write storm before Redis; `auth.redis.degraded_mode_activations` must stay 0.
- `SecurityInvariantsStartupFilter` semantics: Redis outage ⇒ 503, never
  fail-open.

### 4.3 Scenario D2 — cascade

With Redis dead, `HybridSessionBlacklistCache` falls back to PostgreSQL
(write-through). Expect Npgsql pool saturation and 503s; verify the DB is
not corrupted and recovers when Redis returns.

### 4.4 Scenario D3 — Keycloak isolation

```bash
k6 run --quiet -e KC_TOKEN_URL=https://keycloak.../realms/<realm>/protocol/openid-connect/token \
  -e KC_CLIENT_ID=sentinel-load-client -e KC_CLIENT_SECRET=... \
  -e KC_RATE=2000 tests/load/keycloak-token-load.js
```

Refresh-token rotation writes to PostgreSQL; lock contention surfaces as
5xx/429. Triage: Infinispan `owners=2` / `num_segments=256`, `bruteForceProtected`
thresholds, Keycloak PG `max_connections`, scale horizontally.

## 5. Metric Reference (REAL Names)

OTel → Prometheus conversion (`.`, `-` → `_`; counter suffix `_total`).

| Metric | Purpose | Gate/alert |
|---|---|---|
| `auth_dpop_failures_total` | DPoP validation storms | `validate-sre-soak.sh`: ≤ 1,000/5m; alert `DpopFailureSurge` |
| `auth_jti_replays_total` | replay-attempt signal | watch (spike = replay-cache pressure) |
| `auth_token_issued_total` | token issuance volume | cross-check against k6 completed requests |
| `auth_token_validation_duration_seconds` | p99 validation latency (histogram) | p99 ≤ 50ms; `LatencySlaBreached` alert |
| `auth_redis_degraded_mode_activations_total` | fail-closed transitions | 0 during B/A; >0 expected only in D1/D2; `RedisDegradedModeActivated` alert |
| `container_memory_working_set_bytes` | leak detection (cAdvisor) | slope ≤ 0 (12h); `NativeAotMemoryLeakDetected` alert |
| `node_sockstat_TCP_tw` | socket exhaustion | ≤ 20,000/node; `SocketExhaustionImminent` alert |
| `http_server_request_duration_seconds` | OTel ASP.NET Core instrumentation | cross-check |
| `npgsql_pool_active_connections / max` | PG pool saturation | > 0.85 → scale (needs Npgsql metrics enabled, §7.3) |

The `sre-load-gate.yml` CI gate validates these against the live cluster's
Prometheus after each smoke run.

## 6. Distributed Gate Operations

### 6.1 Install the operator

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm install k6-operator grafana/k6-operator -n k6-system --create-namespace
```

### 6.2 Prepare the script ConfigMap + DPoP pool Secret

The configmap must contain **both** `sentinel-sre-suite-xk6.js` and its import
`sentinel-sre-core.js`; the pool secret is mounted at `/pool/dpop-pool.json`
(CRD volume `sentinel-dpop-pool`):

```bash
node tests/scripts/mint-dpop-pool.mjs --count 120 --out tests/load/dpop-pool.json
kubectl -n sentinel-prod create configmap sentinel-sre-script \
  --from-file=sentinel-sre-suite-xk6.js=tests/load/sentinel-sre-suite-xk6.js \
  --from-file=sentinel-sre-core.js=tests/load/sentinel-sre-core.js
kubectl -n sentinel-prod create secret generic sentinel-dpop-pool \
  --from-file=dpop-pool.json=tests/load/dpop-pool.json
```

### 6.3 Run & validate

```bash
kubectl apply -f infra/k8s/sre/crd-spike-20k.yaml
# success = .status.stage == 'finished' (failed runs land in aborted/error)
kubectl get k6/sentinel-spike-20k -n sentinel-prod -o jsonpath='{.status.stage}'
# then validate metrics (needs Prometheus reachable):
PROM_URL=https://prometheus... tests/scripts/validate-sre-soak.sh tests/load/sre-summary.json
```

`Kind: K6` (k6.io/v1alpha1) matches the operator; `TestRun` is the successor
kind for newer operator versions — both take the same `spec`.

### 6.4 CI

- `.github/workflows/sre-load-gate.yml` — smoke battery against the live
  cluster on every relevant push (stock k6, local runner).
- `.github/workflows/sre-distributed-gate.yml` — workflow_dispatch: builds
  the xk6 image, provisions a KinD stack, installs the operator, executes a
  4-runner spike, and fails on any runner failure.

## 7. Remediation Playbook (Gate Failures)

| Symptom | Root cause | Fix |
|---|---|---|
| p99 validation spikes > 50ms | GC pauses / allocation pressure in the DPoP pipeline | Confirm `SecurityContextHasher`/`PrivacyPreservingHasher` `stackalloc` paths; body reads via `ArrayPool<byte>.Shared`; profile `DpopValidationMiddleware` allocations |
| `auth_redis_degraded_mode_activations_total` > 0 during spike | StackExchange.Redis multiplexer queue overflow (default `SyncTimeout` 5000ms blocks threads) | Reduce `SyncTimeout` (config key `SyncTimeout`, `RedisOptions.cs:29`) to ~100ms; `L1AntiFloodCache` already absorbs bursts; ensure `SocketManager` high-priority threads |
| Thread pool injection delays on the 0→20k ramp | .NET ThreadPool warm-up | `ThreadPool.SetMinThreads(500, ...)` at host startup (not yet in code — open tuning item) |
| Keycloak 503/429 on /token | `bruteForceProtected` thresholds or connection-pool limits | Scale Keycloak horizontally; Infinispan `owners=2`, `num_segments=256`; PG `max_connections` sizing; `persistent-user-sessions` to offload Infinispan |
| Npgsql pool saturation > 85% | Cascade fallback under load | Verify write-through batching; scale PG; enable `npgsql_pool_*` metrics for evidence |
| Socket exhaustion in runners | ephemeral-port pressure | §3.2 sysctls; verify HTTP/2 (`h2`) is actually negotiated |

## 8. The 99.99% Proof (Fail-Closed, Never Fail-Open)

A load test is not successful because latency is low; it is successful when
**Redis killed at 15,000 RPS** produces instant `503 Service Unavailable`
(with `Retry-After`) and **zero** requests pass without replay protection.
Run: `make chaos-gate CHAOS_SCENARIO=redis-kill K6_RATE=5000` →
`tests/scripts/validate-fail-closed.sh` asserts 503-dominant responses.
Constitution §III.1: degraded mode is a *state*, not a bypass.

## 9. Capacity Matrix (Scenario C Output)

| Sizing | Pods (4vCPU/8GB) | RPS @ p99<200ms | Error % | Notes |
|---|---|---|---|---|
| 1 pod | 1 | | | |
| N pods @ 20k RPS | N+2 | 20,000 | < 1% | N+2 redundancy per Constitution |
| Redis/Keycloak headroom | — | | | D3 results |

## 10. Cadence

| When | What |
|---|---|
| Every push to `infra/k8s/sre/**` etc. | `sre-load-gate.yml` smoke battery (live cluster) |
| Before every major release | Spike 20k (distributed) + capacity sweep + D1/D2/D3; evidence archived |
| Every 48h (scheduled, on-cluster) | `crd-soak-48h.yaml` soak workload |
| On demand | `sre-distributed-gate.yml` (dispatch) |