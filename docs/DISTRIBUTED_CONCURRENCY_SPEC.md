# Multi-Pod Distributed Nonce & Replay Race Testing: High-Assurance Architecture & Verification

> **Document ID**: SEC-ARCH-002
> **Status**: APPROVED
> **Compliance Baseline**: FAPI 2.0 Advanced · NIST SP 800-63B · FedRAMP High · OWASP API Top 10
> **Scope**: Distributed State Management, Concurrency Verification, Chaos Engineering, TOCTOU Mitigation

---

## 1. Executive Summary

In a multi-pod, horizontally scaled API gateway, enforcing sender-constrained token validation (RFC 9449 DPoP) and replay resistance (RFC 7519 JTI) introduces severe distributed systems challenges. When two identical requests hit different pods at the exact same millisecond, naive `GET`-then-`SET` cache patterns result in **Time-of-Check to Time-of-Use (TOCTOU)** race conditions, allowing token replay, double-spending, and nonce reuse.

This document defines Sentinel's **High-Assurance Architecture** for distributed state management and the **Verification Suite** used to systematically prove the absence of race conditions. By combining atomic Redis operations, systematic concurrency exploration (Microsoft Coyote), and distributed chaos engineering (KinD + Chaos Mesh), Sentinel guarantees **fail-closed invariants** under catastrophic infrastructure failure.

---

## 2. Core Architectural Invariants (The "Fixed" State)

To survive multi-pod concurrency, Sentinel strictly prohibits application-level locking for security-critical state. All state transitions are delegated to Redis atomic operations.

### 2.1 JTI Replay Cache (Atomic `SETNX`)

The JTI (JWT ID) replay cache prevents access token reuse. In a multi-pod environment, Pod A and Pod B might receive the same token simultaneously.

-   **Anti-Pattern**: `if (!cache.Exists(jti)) { cache.Set(jti); }` (Vulnerable to TOCTOU).
-   **Sentinel Invariant**: Use Redis `SET key value EX ttl NX` (Set if Not eXists) via StackExchange.Redis `When.NotExists`.
-   **Behavior**: Only the first pod to execute the command succeeds. The second pod receives a `false` result and immediately rejects the request with `401 Unauthorized` and a `auth.jti.replays_total` SIEM event.
-   **Implementation**: `RedisJtiReplayCache.TryStoreIfNotExistsAsync` (`src/Sentinel.Redis/Stores/RedisJtiReplayCache.cs`).

### 2.2 DPoP Nonce Consumption (Lua Atomic Compare-and-Delete)

DPoP nonces are single-use, per-client-thumbprint challenges. If a client retries a request due to network jitter, multiple pods might attempt to consume the same nonce.

-   **Sentinel Invariant**: A Lua script executes atomically inside Redis to read, compare, and delete the nonce in a single operation.
-   **Behavior**: If the nonce matches, it is deleted and the request proceeds. If it mismatches (stale/replayed), the pod issues a fresh `DPoP-Nonce` challenge (`401 Use DPoP Nonce`) and increments `auth.dpop.nonce_mismatch_total`.
-   **Implementation**: `RedisDpopNonceStore.ConsumeNonceIfMatchesAsync` (`src/Sentinel.Redis/Stores/RedisDpopNonceStore.cs`).

### 2.3 Idempotency State Machine (Distributed Locking)

For mutating operations (e.g., financial transfers), Sentinel enforces RFC 9110 Idempotency.

-   **State Machine**: `UNKNOWN` → `IN_PROGRESS` → `COMPLETED`.
-   **Sentinel Invariant**: The `IN_PROGRESS` lock is acquired via `SET NX` with a short TTL (5 seconds). If acquired, the pod executes the business logic and upgrades the key to `COMPLETED` with the cached HTTP response. If the lock is held by another pod, the requesting pod returns `409 Conflict` and increments `auth.idempotency.lock_contention_total`.
-   **Implementation**: `RedisIdempotencyStore.TryAcquireAsync` (`src/Sentinel.Redis/Stores/RedisIdempotencyStore.cs`), enforced by `IdempotencyFilter` and the `.RequireIdempotency()` endpoint extension.

---

## 3. The Threat Model: Distributed Race Conditions

| Threat ID | Threat Description | Category | Impact | Primary Mitigation |
|---|---|---|---|---|
| **T-RC-01** | **TOCTOU Replay**: Two pods process the same JTI simultaneously due to non-atomic cache checks. | Tampering | Critical | Atomic `SET NX` (`When.NotExists`) in `RedisJtiReplayCache`. |
| **T-RC-02** | **Nonce Race**: Concurrent requests consume the same DPoP nonce, breaking single-use semantics. | Tampering | High | Lua script atomic compare-and-delete in `RedisDpopNonceStore`. |
| **T-RC-03** | **Orphaned Locks**: A pod crashes while holding an `IN_PROGRESS` idempotency lock, blocking future retries. | Availability | Medium | Short TTL (5s) on `IN_PROGRESS` state; automatic pruning. |
| **T-RC-04** | **Split-Brain Replay**: Redis cluster partitions; pods fall back to local memory, allowing replays. | Repudiation | Critical | **Fail-Closed**: `ReplayCacheUnavailableException` / `NonceStoreUnavailableException` / `IdempotencyStoreUnavailableException` surface as HTTP 503. No local fallback permitted; `SecurityInvariantsStartupFilter` blocks in-memory store registration outside Development. |

---

## 4. High-Assurance Verification Strategy

Sentinel employs a three-tiered verification strategy to systematically prove the absence of distributed race conditions.

### 4.1 Level 1: Systematic Concurrency Testing (Microsoft Coyote)

Standard unit tests cannot reliably catch race conditions because thread scheduling is non-deterministic. Sentinel uses **Microsoft Coyote** to systematically explore all possible thread interleavings.

-   **Mechanism**: Coyote rewrites the .NET bytecode to take control of the `Task` scheduler. It forces specific interleavings (e.g., Pod A reads cache → Pod B writes cache → Pod A writes cache) to intentionally trigger TOCTOU bugs.
-   **Target**: `Sentinel.Tests.Concurrency` (idempotency acquisition, DPoP nonce consume, JTI marking races).
-   **Gate**: 1,000+ scheduling iterations must pass with zero assertion failures (enforced in `security-pipeline.yml` `test-suites`).

### 4.2 Level 2: Distributed Chaos Engineering (KinD + Chaos Mesh)

To verify behavior under real-world network anomalies, Sentinel deploys the full stack to a local Kubernetes cluster (KinD) and injects chaos via **Chaos Mesh** (eBPF).

-   **Scenario 1 (Redis Pod Kill)**: `k6` blasts the API while Chaos Mesh kills the Redis master pod (`tests/chaos/redis-pod-kill.yaml`).
    -   *Invariant*: 0 successful replays. API must return `503 Service Unavailable` (Fail-Closed).
-   **Scenario 2 (Network Partition)**: Chaos Mesh isolates the API pods from Redis (`tests/chaos/postgres-network-partition.yaml`, `tests/chaos/dns-latency-keycloak.yaml`).
    -   *Invariant*: `NonceStoreUnavailableException` / `ReplayCacheUnavailableException` is thrown; pipeline aborts safely without bypassing security checks.
-   **Gate**: `chaos-gate.yml` (invoke via `make chaos-gate`).

### 4.3 Level 3: SRE Load & Soak Gates (k6)

Continuous verification in CI/CD using `k6` to simulate distributed clock skew and high-contention lock acquisition.

-   **Metric**: `auth.redis.degraded_mode_activations` must remain 0 during standard soak tests.
-   **Metric**: `auth.jti.replays_total` must accurately reflect blocked attempts without false positives.
-   **Gate**: `sre-load-gate.yml` (invoke via `make sre-gate MODE=soak`).

---

## 5. Implementation Guide

### 5.1 Redis Lua Scripts (Atomicity Guarantees)

**DPoP Nonce Consumption** (inlined in `RedisDpopNonceStore.ConsumeNonceIfMatchesAsync`):

```lua
-- KEYS[1] = nonce store key (e.g., "dpop:nonce:{thumbprint}")
-- ARGV[1] = expected nonce value
local current = redis.call('GET', KEYS[1])
if current == ARGV[1] then
    redis.call('DEL', KEYS[1])
    return 1 -- Consumed successfully
else
    return 0 -- Mismatch (stale or replayed)
end
```

**Idempotency Lock Acquisition** (equivalent semantics in `RedisIdempotencyStore.TryAcquireAsync` via `SET key value EX ttl NX` + state read with bounded retry):

```lua
-- KEYS[1] = idempotency key
-- ARGV[1] = "IN_PROGRESS"
-- ARGV[2] = TTL in seconds
local set = redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2], 'NX')
if set then
    return 1 -- Lock acquired
else
    local state = redis.call('GET', KEYS[1])
    if state == "COMPLETED" then
        return 2 -- Already completed (replay cached response)
    else
        return 3 -- In progress by another pod (409 Conflict)
    end
end
```

### 5.2 C# Store Implementation (Snippet)

```csharp
public async Task<bool> TryStoreIfNotExistsAsync(string jti, TimeSpan ttl, CancellationToken ct)
{
    try
    {
        var db = await _provider.GetDatabaseAsync(ct);
        // Atomic SETNX: Prevents TOCTOU across multi-pod deployments
        var created = await db.StringSetAsync(
            $"replay:jti:{jti}",
            RedisValue.Null,
            ttl,
            When.NotExists,
            CommandFlags.None);

        return created;
    }
    catch (RedisConnectionException ex)
    {
        // FAIL-CLOSED: Never fall back to local memory or bypass cache
        throw new ReplayCacheUnavailableException("Redis cluster unreachable during JTI check", ex);
    }
}
```

### 5.3 Coyote Test Harness Configuration

`Sentinel.Tests.Concurrency` runs under Coyote with `RunCoyoteRewrite=true`; the CI gate executes 1,000 scheduling iterations (`WithTestingIterations(1000)`) and fails on any reported bug:

```csharp
var configuration = Configuration.Create().WithTestingIterations(1000);
var engine = TestingEngine.Create(configuration, async () =>
{
    // Simulate 10 concurrent pods attempting the same Idempotency-Key
    var tasks = Enumerable.Range(0, 10).Select(_ => _store.TryAcquireAsync("key-1", TimeSpan.FromSeconds(5), CancellationToken.None));
    var results = await Task.WhenAll(tasks);

    // Invariant: Exactly ONE pod acquires the lock.
    results.Count(r => r.State == IdempotencyAcquireResult.Acquired).Should().Be(1);

    // Invariant: All other pods see InProgress or Completed.
    results.Count(r => r.State == IdempotencyAcquireResult.InProgress).Should().Be(9);
});

engine.Run();
Assert.Empty(engine.TestReport.Bugs);
```

### 5.4 Chaos Mesh Manifest (`tests/chaos/redis-pod-kill.yaml`)

```yaml
apiVersion: chaos-mesh.org/v1alpha1
kind: PodChaos
metadata:
  name: redis-pod-kill
  namespace: sentinel-prod
spec:
  action: pod-kill
  mode: all
  selector:
    namespaces:
      - sentinel-prod
    labelSelectors:
      app.kubernetes.io/name: redis
      redis-role: master
  schedule: "*/2 * * * *" # Kill master every 2 minutes during load test
  duration: "10s"
```

---

## 6. Observability & Fail-Closed Telemetry

To detect distributed race anomalies in production, Sentinel emits the following OpenTelemetry metrics (defined in `src/Sentinel.Security.Diagnostics/AuthTelemetry.cs`, meter `Sentinel.Auth.Metrics`) mapped to SRE alerts:

| Metric Name | Type | Alerting Threshold | Severity | Meaning |
|---|---|---|---|---|
| `auth.jti.replays_total` | Counter | > 5 / min | **Sev-1** | Active distributed replay campaign detected. |
| `auth.redis.degraded_mode_activations` | Counter | > 0 | **Sev-1** | Pods lost quorum; fail-closed triggered. |
| `auth.idempotency.lock_contention_total` | Counter | > 100 / min | **Sev-2** | High retry rate or orphaned locks (TTL misconfiguration). |
| `auth.dpop.nonce_mismatch_total` | Counter | > 50 / min | **Sev-2** | Client clock skew or aggressive retry logic. |

**Runbook Action**: If `auth.jti.replays_total` spikes, correlate via W3C `traceId`. If the source IPs are distributed, assume token theft. Invoke Keycloak Admin API to globally revoke the subject's sessions. **Do not disable the replay cache.**

---

## 7. Audit & Compliance Mapping

| Standard | Control Objective | Sentinel Evidence |
|---|---|---|
| **FAPI 2.0 Advanced** | Sender-Constrained Token Use & Replay Resistance | `RedisJtiReplayCache` (Atomic SETNX), `RedisDpopNonceStore` (Lua Script). |
| **NIST SP 800-63B** | AAL3 / Replay Resistance | Coyote systematic concurrency tests prove zero TOCTOU vulnerabilities. |
| **FedRAMP High** | System Integrity & Availability | Chaos Mesh `redis-pod-kill` proves fail-closed (503) behavior under partition. |
| **OWASP API Top 10** | API4: Unrestricted Resource Consumption | Idempotency locks prevent double-spending during distributed network retries. |

---

## 8. Pre-Release Verification Checklist

Before merging any changes to `Sentinel.Redis`, `Sentinel.AspNetCore.Middleware`, or `Sentinel.Session`, the following gates **must** pass:

- [ ] **Coyote Gate**: `dotnet coyote test` passes 1,000 iterations with 0 bugs (CI: `test-suites` Concurrency job).
- [ ] **Chaos Gate**: `make chaos-gate SCENARIO=redis-kill` passes (0 successful replays during pod death).
- [ ] **Load Gate**: `make sre-gate MODE=soak` passes (p99 latency < 50ms, 0 degraded mode activations).
- [ ] **Code Review**: Security Reviewer verifies no `GET`-then-`SET` patterns exist in security-critical paths.
- [ ] **Telemetry**: unit tests in `Sentinel.Tests.Unit/Unit/DistributedTelemetryTests.cs` verify counter increments for contention and nonce mismatch events.
