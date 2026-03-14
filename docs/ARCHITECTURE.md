# Sentinel Architecture Decision Records (ADRs)

## ADR-001: DPoP (Demonstration of Proof-of-Possession) as Sender-Constraint Mechanism

**Status:** Accepted  
**Date:** 2026-03-15  
**Decision Makers:** Security Architecture Review Board

### Context

Sentinel must prevent unauthorized bearer token usage (token theft, interception). Three approaches were evaluated:
1. mTLS binding only (cnf.x5t#S256)
2. DPoP only (RFC 9449)
3. DPoP + optional mTLS (defense-in-depth)

### Decision

**Adopt DPoP (RFC 9449) as primary sender-constraint with optional mTLS as second factor.**

- DPoP validates proof-of-possession via JWK-signed proof of access token
- Proof includes HTTP method (htm), URI (htu), and JTI replay protection
- mTLS certificate binding (cnf.x5t#S256) available as optional second factor for high-value Operations

### Rationale

- **RFC 9449 alignment:** FAPI 2.0 Baseline requires sender-constraint; DPoP is standard pattern
- **Zero infrastructure changes:** Works with any HTTP client supporting JWK signing; no certificate distribution
- **Nonce challenge-response:** Rotating perimeter nonces prevent proof reuse across endpoints
- **Fail-closed:** Missing DPoP proof → 400 with HTTP 503 and `use_dpop_nonce` challenge issued

### Implications

- Client must generate proof for every request (proof JTI has 60s TTL)
- Clients without JWK support cannot authenticate; fallback to Keycloak client credentials flow
- Nonce lifecycle management adds state to backend (Redis-backed store)
- Metrics: ~5ms proof validation overhead per request

---

## ADR-002: Atomic Redis-Backed Replay Cache with SET NX Semantics

**Status:** Accepted  
**Date:** 2026-03-15

### Context

JTI replay attacks allow token reuse if not detected. Naive solutions:
1. SQL-backed cache (transactional INSERT IGNORE; high latency)
2. Redis SET followed by GET check (TOCTOU race)
3. Redis SET NX with TTL (atomic, O(1))

### Decision

**Implement replay detection via Redis `StringSetAsync(key, value, When.NotExists)` with expiration.**

Cache entries:
- `jti:token:{jti}` → token JTI (60s TTL per token lifetime)
- `jti:proof:{jti}` → proof JTI (60s TTL per proof lifespan)

Validation:
```csharp
var wasStored = await db.StringSetAsync(key, "used", ttl, When.NotExists);
if (!wasStored) return Result.Invalid("JTI already used");
```

### Rationale

- **Atomicity:** No race window; SET NX is atomic (no check + set sequence)
- **Latency:** Sub-millisecond for cache hits (single Redis command)
- **Fail-closed:** If Redis is unavailable, exception bubbles to middleware guard and returns 503
- **TTL alignment:** Proof TTL matches token lifetime (60s); no stale entries

### Implications

- Redis downtime blocks all token usage (fail-closed by design)
- Cache miss for replayed JTI cannot distinguish stale (expired) vs legitimate (first use) — must reject both
- Metrics: p99 cache operation < 2ms under normal load

---

## ADR-003: Per-Thumbprint Rotating Nonce Challenge-Response Pattern

**Status:** Accepted  
**Date:** 2026-03-15

### Context

Attackers can replay valid proofs if nonce requirement is missing. Nonce lifecycle options:
1. Server-issued nonce, client must include in next proof (stateful, need per-client storage)
2. Stateless nonce (base64(HMAC(secret, client_id)) — security via entropy, not state)
3. Per-JWK-thumbprint nonce (tied to specific client identity, enforces rotation)

### Decision

**Issue rotating per-JWK-thumbprint nonces; client includes nonce in next request's proof.**

Flow:
1. Anonymous request → 400 with `use_dpop_nonce` challenge + nonce in `DPoP-Nonce` header
2. Client includes nonce in next proof's `nonce` claim
3. Server validates nonce matches expected value, marks as consumed (never reused)
4. Response includes new `DPoP-Nonce` for next request

Nonce state:
- `nonce:{thumbprint}` → current nonce (60s TTL, renewable)
- Consumption atomic via Redis transaction (compare-delete)

### Rationale

- **RFC 9449 §4.3 compliance:** Per-proof nonce prevents replay
- **Per-identity isolation:** Different JWKs have independent nonce sequences; no cross-client nonce leakage
- **Atomic consumption:** Compare-delete transaction ensures consumed nonce never reused (no race)
- **Client transparency:** Nonce automation possible in SDK; no manual tracking needed

### Implications

- All unauthenticated requests initially fail with 400 + challenge (expected behavior)
- Nonce expiration (60s) requires client retry with new challenge
- Stale nonce (consumed but client retries) triggers new challenge issuance
- Metrics: nonce operations < 1ms; challenge issuance < 5ms

---

## ADR-004: Dual-Partition Chained Rate Limiter (Identity + IP)

**Status:** Accepted  
**Date:** 2026-03-15

### Context

Rate limiting attack surface:
1. Per-IP only → unauthenticated bots share quota; DoS via many requests from single IP
2. Per-identity only → multi-client DoS via quota exhaustion of legitimate user
3. Per-path only → high-value endpoints (token refresh) rate-limited separately but not globally

### Decision

**Implement chained rate limiter with two partition keys:**
1. **Identity partition:** `{subject_id}:{client_id}` if authenticated; `{ip_address}` if anonymous
2. **IP partition:** Always `{ip_address}` (secondary enforcement)

Both partitions must have available quota; if either exhausted → 429 Too Many Requests.

```
Check: AllowAsync(partition1="sub:client_id", partition2="ip:1.2.3.4")
→ identity quota OK? YES
→ IP quota OK? YES
→ ALLOW
→ identity quota OK? NO
→ DENY single-request or token refreshes 429 immediately
```

### Rationale

- **Anonymous DoS prevention:** Each anonymous IP gets separate quota (no shared bucket)
- **Authenticated exhaustion defense:** Even with quota, per-IP guard prevents extreme volume
- **Graduated response:** Web traffic (low quota) vs API (higher quota) via partition-specific config
- **Observable:** Both partitions logged; ops can identify attacker profile (single IP vs coordinated identities)

### Implications

- Dual-quota decision tree adds ~1ms latency (acceptable)
- Azure DDoS or AWS Shield upstream recommended (application-layer only covers authenticated + direct IP)
- Anonymous users must have separate infra quota (CDN edge limit) to avoid platform-level DoS
- Metrics: partition hit rate, quota exhaustion events

---

## ADR-005: Configurable Session Blacklist TTL Aligned with Keycloak SSO Lifespan

**Status:** Accepted  
**Date:** 2026-03-15

### Context

Session invalidation during logout must survive token lifetime. Mismatch scenarios:
1. Token TTL = 5m, blacklist TTL = 5m → token expires naturally, no invalidation needed
2. Token TTL = 1h, blacklist TTL = 5m → logout ineffective; token still valid after 5m
3. Token TTL = 1h, blacklist TTL = 25h → excessive memory; orphaned entries after token expires

### Decision

**Set session blacklist TTL to Keycloak `SsoSessionMaxLifespanSeconds` config (default 8 hours).**

Configuration:
```json
"Keycloak": {
  "SsoSessionMaxLifespanSeconds": 28800
}
```

Resolved by:
1. Explicit `Keycloak:SsoSessionMaxLifespanSeconds` in appsettings.json
2. Fallback to `Keycloak:SessionMaxLifespanSeconds` if not set
3. Hard default: 28800 seconds (8 hours)

Blacklist storage:
```csharp
var ttl = TimeSpan.FromSeconds(configuredSeconds);
await cache.BlacklistSessionAsync(sessionId, ttl, cancellationToken);
```

### Rationale

- **Alignment:** Keycloak's SSO session lifetime is authoritative; Sentinel respects same TTL
- **Consistency:** Logged-out sessions cannot be reused before natural token expiration
- **Memory efficiency:** No stale blacklist entries beyond token lifetime
- **Configurability:** Ops can tune lifespan without code changes

### Implications

- Blacklist operations: Redis DEL on logout, TTL-based expiration
- If Keycloak config changes, Sentinel respects new TTL on next logout
- Audit log records session TTL at logout time (drift detection)
- Metrics: blacklist hit rate, average TTL

---

## ADR-006: Middleware Ordering: Authentication → RateLimiter → DPoP Validation

**Status:** Accepted  
**Date:** 2026-03-15

### Context

Security middleware execution order affects threat coverage:

**Option A: RateLimiter → DPoP → Auth**
- Pros: Early rate limit blocks malformed requests
- Cons: DPoP validation before JWT auth; unsigned proof can't bind to token

**Option B: Auth → DPoP → RateLimiter**
- Pros: DPoP validates signature after JWT asserts identity
- Cons: `sub` not available for identity-partition rate limiting

**Option C: Auth → RateLimiter → DPoP** (Selected)
- Pros: Full JWT claims available for rate limit identity partition; DPoP validates proof post-quota check

### Decision

**Order: Authentication → RateLimiter → DPoP Validation**

Pipeline:
```
[ExceptionHandler] → [SecurityHeaders] → [Auth] → [RateLimiter] → [DPoP] → [mTLS] → [ACR] → [Authz] → [Endpoint]
```

Key invariants:
- `HttpContext.User` (JWT claims) available to `PartitionedRateLimiter`
- Rate limit decision based on authenticated identity or IP
- DPoP proof validated post-quota (prevents unbounded DPoP crypto work)

### Rationale

- **DoS efficiency:** Rate limiter blocks high-volume attackers before crypto operations
- **Auth + identity:** Full JWT context available for granular rate limit decisions
- **DPoP ordering:** Validates proof after auth (can bind proof to token claims)
- **Observable:** All rate limit decisions logged with authenticated identity context

### Implications

- Unauthenticated requests hit IP-only rate limit
- Authenticated requests use identity partition
- DPoP validatons occur post-quota; failures don't consume quota
- Metrics: partition-specific hit rates, auth-to-RateLimiter conversion

---

## ADR-007: Idempotency State Machine: IN_PROGRESS (409) vs. COMPLETED (204)

**Status:** Accepted  
**Date:** 2026-03-15

### Context

Logout operations must be idempotent (repeated calls safe). State options:
1. Stateless (no tracking) → repeated requests complete twice (bad for audit)
2. Single flag (COMPLETED) → unclear if retry is stale retry or new request
3. State machine (IN_PROGRESS vs COMPLETED) → explicit distinction

### Decision

**Implement state machine with two redis keys:**
- `idempotency:{request_id}:in_progress` → operation started (5m TTL)
- `idempotency:{request_id}:completed` → operation finished (24h TTL)

Retry logic:
```
GET in_progress_key:
  → Exists? → return 409 Conflict (retry in progress)
  → Missing? → check completed_key

GET completed_key:
  → Exists? → return 204 No Content (already completed)
  → Missing? → proceed with operation
    → SET in_progress_key
    → Execute logout
    → DEL in_progress_key
    → SET completed_key
    → return 204 No Content
```

### Rationale

- **Conflict distinction:** 409 signals retry unsafe (operation in-flight); 204 signals safe (already done)
- **Resource idempotency:** Client retries get same response without side effects
- **Audit compliance:** Audit log records single completion event; retries don't duplicate entries
- **TTL alignment:** IN_PROGRESS < token lifetime (5m); COMPLETED = session TTL (24h)

### Implications

- Request ID (`Idempotency-Key` header) required for logout operations
- In-flight operations (hanging for >5m) are treated as completed on next retry
- Audit log correlates request ID with completion time
- Metrics: retry rate, in-progress timeout rate

---

## ADR-008: Fail-Closed JWT Replay Failure Handling (Direct 503 Response)

**Status:** Accepted  
**Date:** 2026-03-15

### Context

If JWT JTI is already used, token is replayed. Response handling options:
1. Pass-through to endpoint → endpoint must handle 401
2. Middleware returns 401 directly → consistent response
3. Middleware returns 503 on replay detection → signals server state, not client error
4. Post-request flag + middleware inspection → delayed response, out-of-band handling

### Decision

**On JWT replay detection (JTI already in cache), immediately return 503 Service Unavailable via OnChallenge handler.**

Implementation:
```csharp
options.Events = new JwtBearerEvents
{
    OnChallenge = async ctx =>
    {
        if (ctx.Exception is SecurityTokenException && ctx.HttpContext.Items.ContainsKey("JtiReplayDetected"))
        {
            ctx.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            ctx.Response.ContentType = "application/problem+json";
            await ctx.Response.WriteAsJsonAsync(new ProblemDetails
            {
                Type = "/errors/token-reuse-detected",
                Title = "Token Already Used",
                Status = 503
            });
            ctx.HandleResponse(); // Prevent default response
        }
    }
};
```

### Rationale

- **Fail-closed:** Replayed token treated as authorization failure, not success
- **503 semantics:** Replay detection indicates server state exhaustion (cache hit), not client error
- **Direct response:** No middleware post-processing; immediate rejection prevents execution leakage
- **Observable:** Caller sees 503 and can retry after jitter (standard HTTP retry semantics)

### Implications

- Replayed tokens never reach endpoint handlers (security check pre-request)
- Caller must distinguish 503 (retry) from 401 (client error) in handling
- Metrics: JWT replay detection rate, 503 response frequency
- Telemetry: security event logged with JWT replay context

---

## ADR-009: Redis Deterministic Port Assignment for Test Fixture Stability

**Status:** Accepted  
**Date:** 2026-03-15

### Context

Integration tests using Testcontainers for Redis/Keycloak must start services reliably. Port assignment options:
1. OS-assigned random ports (0) → flaky test discovery (port conflicts, incorrect DNS)
2. Fixed port (6380) → collisions if multiple test runs overlap
3. Hardcoded ports + readiness polling → deterministic, requires TCP validation

### Decision

**Hardcode ports: Redis 6380, Keycloak 6381; add WaitForReadinessAsync() TCP polling (30s timeout).**

Test fixture:
```csharp
private static readonly int RedisPort = 6380;
private static readonly int KeycloakPort = 6381;

private async Task WaitForRedisReadinessAsync(CancellationToken cancellationToken)
{
    var sw = Stopwatch.StartNew();
    while (sw.Elapsed < TimeSpan.FromSeconds(30))
    {
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync("localhost", RedisPort, cancellationToken);
            return;
        }
        catch { await Task.Delay(100, cancellationToken); }
    }
    throw new TimeoutException("Redis readiness check failed after 30s");
}
```

### Rationale

- **Reproducibility:** Same port avoids ephemeral allocation conflicts
- **Debugging:** Test logs reference consistent ports (6380, 6381)
- **Efficiency:** TCP polling (100ms interval) fast-detects readiness without external tools
- **Failure visibility:** Clear timeout errors if containers don't start

### Implications

- Test machine cannot run other services on 6380/6381
- CI/CD container must expose these ports
- Test isolation: each test run gets fresh containers (compose down before up)
- Metrics: fixture startup latency (target <5s for Redis, <15s for Keycloak)

---

## ADR-010: Security Telemetry via OpenTelemetry Activities with Structured Events

**Status:** Accepted  
**Date:** 2026-03-15

### Context

Security events (failures, challenges, rate limits) must be auditable. Logging options:
1. Unstructured logs → difficult to parse, correlate
2. Structured logs (JSON) → parseable but missing trace context
3. OpenTelemetry Activities → W3C trace context, distributed tracing, correlation IDs

### Decision

**Emit security events as OpenTelemetry Activity events with structured attributes.**

Example:
```csharp
var activity = Activity.Current;
if (activity != null)
{
    activity.AddEvent(new ActivityEvent(
        "security:invalid_dpop_proof",
        new ActivityTagsCollection(new Dictionary<string, object?>
        {
            ["error.type"] = "invalid_signature",
            ["request.method"] = "POST",
            ["security.outcome"] = "failure",
            ["http.response.status_code"] = 400,
            ["enduser.id"] = principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value
        })
    ));
}
```

Events emitted for:
- `security:authentication_success` (JWT validated, nonce consumed)
- `security:invalid_dpop_proof` (proof validation failed)
- `security:use_dpop_nonce` (nonce challenge issued)
- `security:token_reuse_detected` (JTI replay)
- `security:rate_limit_exceeded` (quota exhausted)
- `security:session_revoked` (logout completed)

### Rationale

- **Correlation:** TraceID ties events across distributed components
- **Structure:** Standardized attributes enable automated alerting
- **Performance:** Activity cost is negligible (microseconds); can be sampled at exporter level
- **Observability:** Events integrate with X-Ray, Jaeger, Application Insights

### Implications

- OpenTelemetry exporter configuration required (Jaeger, Prometheus, Azure Monitor, etc.)
- Sampling strategy affects log volume (start with 100%, tune down if needed)
- Sensitive data (PII) must be excluded from activity attributes
- Metrics: event throughput, exporter latency

---

## Summary Table

| ADR | Title | Status | Trade-off |
|-----|-------|--------|-----------|
| 001 | DPoP as Sender-Constraint | ✅ Accepted | Proof generation overhead (~5ms); client JWK support required |
| 002 | Atomic Redis SET NX Replay Cache | ✅ Accepted | Redis dependency; fail-closed on outage |
| 003 | Per-Thumbprint Rotating Nonce | ✅ Accepted | Initial 400 for anonymous; stateful nonce store |
| 004 | Dual-Partition Chained Rate Limiter | ✅ Accepted | Identity + IP overhead (~1ms); requires upstream DDoS defense |
| 005 | Configurable Session Blacklist TTL | ✅ Accepted | Config drift must be monitored; default fallback 28800s |
| 006 | Auth → RateLimiter → DPoP Pipeline | ✅ Accepted | Auth failures not rate-limited (by design) |
| 007 | Idempotency State Machine | ✅ Accepted | Request ID header required; 5m in-flight timeout |
| 008 | Fail-Closed JWT Replay via 503 | ✅ Accepted | Non-standard 503 semantics; clients must handle retry |
| 009 | Deterministic Redis Port (6380) | ✅ Accepted | Port conflicts if other services running |
| 010 | OpenTelemetry Security Events | ✅ Accepted | Exporter config required; sensitive data scrubbing needed |

