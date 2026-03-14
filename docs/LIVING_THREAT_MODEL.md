# Sentinel Living Threat Model

**Last Updated:** 2026-03-15  
**Classification:** INTERNAL ONLY  
**Threat Level:** HIGH (handles sensitive authentication tokens)

---

## Executive Summary

Sentinel is a DPoP-protected authentication API processing sensitive access tokens, refresh tokens, and session state. This living threat model identifies attack surfaces, threats, and implemented mitigations.

**Key Assets:**
- Access tokens (short-lived, high-value)
- Refresh tokens (long-lived, enables privilege escalation)
- Session state (Redis-backed, tied to user identity)
- DPoP proof key material (client-held, regenerates per-request)

**Primary Attackers:**
- Token theft (network interception, XSS, malicious third-party)
- Replay attacks (captured proof/token reused across contexts)
- Brute-force (token enumeration, refresh token prediction)
- Rate-limit bypass (anonymous partition or per-IP exhaustion)
- Privilege escalation (insufficient ACR, scope overflow)

---

## Threat Categories

### 1. Token Theft & Unauthorized Use

#### 1.1 Bearer Token Interception

**Threat:** Attacker eavesdrops on network (MITM, rogue WiFi) and captures access token.

**Impact:** Attacker can impersonate user, access protected resources indefinitely (until token expiration).

**Likelihood:** MEDIUM (HTTPS mitigates, but TLS stripping / certificate substitution possible)

**Mitigations:**
- ✅ HTTPS/TLS 1.2+ enforced (HSTS header)
- ✅ Security response headers: `Strict-Transport-Security: max-age=31536000`
- ✅ Certificate pinning recommended client-side (optional)
- ✅ DPoP binding (access token tied to client JWK; token alone insufficient)

**Residual Risk:** MEDIUM → LOW (DPoP requires matching JWK; stolen token alone useless without proof-signing capability)

---

#### 1.2 Refresh Token Compromise

**Threat:** Attacker steals refresh token and generates new access tokens indefinitely.

**Impact:** CRITICAL (unlimited impersonation even after original session logout; long-lived exploit window).

**Likelihood:** MEDIUM-HIGH (refresh token often stored in persistent storage; XSS or malware can exfiltrate)

**Mitigations:**
- ✅ Refresh token rotation on every use (old token invalidated)
- ✅ Token reuse detection via JTI cache (second use detected, session blacklisted)
- ✅ Refresh token lifetime configurable (default 30 days, aligned with Keycloak)
- ✅ Secure storage recommended: HttpOnly, Secure, SameSite cookies or LocalStorage + XSS guards
- ✅ Session blacklist on logout (TTL aligned with Keycloak SSO session)

**Residual Risk:** MEDIUM (rotated tokens limit exposure; reuse detection catches second use; but first use window is unguarded)

---

#### 1.3 XSS-Based Token Exfiltration

**Threat:** Injected JavaScript reads access/refresh tokens from DOM or cookies, sends to attacker server.

**Impact:** CRITICAL (token theft + automated impersonation).

**Likelihood:** HIGH (if client app has XSS, common in SPAs).

**Mitigations:**
- ⚠️ **NOT Sentinel-specific:** Sentinel does not execute browser code; responsibility on client app
- ✅ Recommended client-side mitigations:
  - HttpOnly cookies (JavaScript cannot access)
  - Content Security Policy (CSP) blocking external scripts
  - Subresource Integrity (SRI) for CDN-hosted libraries
  - Token lifetime minimization (access: 15m, refresh: 30d)

**Residual Risk:** HIGH (XSS is pervasive; HttpOnly cookies eliminate JavaScript exfiltration but CSRF becomes risk)

---

### 2. Replay & Reuse Attacks

#### 2.1 Access Token Replay

**Threat:** Attacker captures valid access token and reuses it across multiple requests (e.g., to different endpoints, from different IP).

**Impact:** CRITICAL (unbounded impersonation; token valid for full lifetime unless revoked).

**Likelihood:** MEDIUM (requires network access to capture token; short-lived (1h) limits scope).

**Mitigations:**
- ✅ JWT JTI (unique identifier) stored in atomic Redis cache
- ✅ Replay detection: `SET NX` prevents second use of same JTI
- ✅ Proof uniqueness: Token bound to DPoP proof JTI (different proof required per-request)
- ✅ Token TTL enforcement (token expires after 1h, naturally preventing infinite reuse)
- ✅ Fail-closed: Cache miss or unavailability → 503, not bypass

**Residual Risk:** LOW (atomic JTI cache + short TTL + proof binding = effective prevention)

---

#### 2.2 DPoP Proof Replay

**Threat:** Attacker captures valid DPoP proof (JWT) and reuses it for same HTTP method + URI with stolen token.

**Impact:** HIGH (one-request unauthorized access; limited by nonce rotation).

**Likelihood:** MEDIUM-HIGH (proof must be captured on wire; many clients log/cache proofs insecurely).

**Mitigations:**
- ✅ Proof JTI uniqueness (like token JTI) → second use blocked
- ✅ Per-thumbprint rotating nonce (proof must include server-issued nonce; stale nonce rejected)
- ✅ 60-second proof lifetime (time window for replay is bounded)
- ✅ Atomic nonce consumption (Redis transaction compare-delete; stale nonce cannot be reused)

**Residual Risk:** LOW (nonce rotation + JTI uniqueness prevent replay across requests)

---

#### 2.3 Refresh Token Reuse (Theft Detection)

**Threat:** Attacker steals refresh token and uses it; legitimate user also uses same token.

**Impact:** HIGH (legitimate user and attacker both generate tokens; attacker gains persistent access).

**Likelihood:** MEDIUM (assumes token compromise + legitimate user unaware).

**Mitigations:**
- ✅ Token rotation on refresh (old token invalidated; attacker's token becomes unusable after user refreshes)
- ✅ Session state tracking (family tree of refreshes; if stale refresh detected, entire family revoked)
- ✅ JTI cache prevents exact reuse (second use of rotated token rejected)
- ✅ Reuse detection triggers session blacklist (all future refreshes fail; user must re-authenticate)

**Residual Risk:** MEDIUM (first use by attacker succeeds; but second use detected and session terminated; requires user awareness to re-authenticate)

---

### 3. Cryptographic Attacks

#### 3.1 DPoP Proof Signature Forgery

**Threat:** Attacker generates valid DPoP proof without possessing client's private key (forges signature).

**Impact:** CRITICAL (forged proof could enable unauthorized access).

**Likelihood:** VERY LOW (RSA-2048, EC P-256, PS256 are cryptographically hard; no known practical forgery)

**Mitigations:**
- ✅ ES256 (EC with SHA-256) standard; resistant to timing attacks
- ✅ Signature verification via `jose` library (constant-time comparison)
- ✅ JWK public key verified against known thumbprint in access token (`cnf.jkt`)
- ✅ Proof claims (htm, htu, iat) are committed by signature

**Residual Risk:** VERY LOW (cryptographic assumptions hold; algorithm negotiated and verified)

---

#### 3.2 JWK Thumbprint Collision

**Threat:** Two different JWKs have same S256 thumbprint (hash collision).

**Impact:** HIGH (attacker could use different key but pass thumbprint validation).

**Likelihood:** NEGLIGIBLE (SHA-256 has 2^256 space; practical collision cost >> benefit)

**Mitigations:**
- ✅ SHA-256 standard (NIST approved) with well-understood security margins
- ✅ Thumbprint computed per RFC 7638 (deterministic, no attack surface)

**Residual Risk:** NEGLIGIBLE (mathematically infeasible with current cryptography)

---

### 4. Rate Limiting & DoS

#### 4.1 Per-Identity Rate Limit Exhaustion

**Threat:** Attacker with valid credentials sends high-volume requests to exhaust per-identity quota, causing denial of service for legitimate requests.

**Impact:** MEDIUM (service degradation; legitimate user blocked from token refresh, logout).

**Likelihood:** HIGH (attacker has valid credentials or knows a credential).

**Mitigations:**
- ✅ Per-identity rate limiter (sub + client_id partitioned)
- ✅ Dual-partition enforcement (identity + IP; IP partition prevents per-identity exhaustion in isolation)
- ✅ Graduated quotas: Auth endpoints 10 req/min, protected 20 req/min (configurable)
- ✅ 429 response with `Retry-After` header

**Residual Risk:** MEDIUM (attacker can still exhaust single identity's quota in legitimate use; requires upstream DDoS protection for multi-IP coordinated attacks)

---

#### 4.2 Anonymous Rate Limit Evasion

**Threat:** Attacker sends many unauthenticated requests, sharing per-IP quota across many endpoints to bypass rate limiting.

**Impact:** MEDIUM (DoS risk; initial requests trigger nonce challenges).

**Likelihood:** MEDIUM (attacker can distribute requests across multiple endpoints if per-path rate limiting used).

**Mitigations:**
- ✅ Global per-IP rate limiter (shared across all endpoints; no per-path partition)
- ✅ Anonymous partition key = IP address (not shared "anonymous" bucket; each IP isolated)
- ✅ Saturating single IP quota blocks that IP from all endpoints

**Residual Risk:** MEDIUM (per-IP quota can still be shared across endpoints; upstream DDoS mitigation recommended)

---

#### 4.3 Distributed DoS (Multi-IP Coordinated Attack)

**Threat:** Botnet sends requests from many IPs, each bypassing per-IP quota; aggregate overwhelms infrastructure.

**Impact:** CRITICAL (Sentinel offline; users cannot authenticate).

**Likelihood:** MEDIUM (requires botnet coordination; common in large-scale attacks).

**Mitigations:**
- ⚠️ **NOT fully addressable by Sentinel:** Application-layer rate limiting insufficient
- ✅ Recommended upstream mitigations:
  - WAF/CDN (AWS Shield, Azure DDoS, Cloudflare)
  - Geographic IP blocking
  - Behavioral analysis (JA3 fingerprinting for bot detection)
  - Rate limiting at edge (CloudFront, Front Door)

**Residual Risk:** MEDIUM-HIGH (Sentinel enforces per-IP limits; upstream DDoS protection required)

---

### 5. Authorization & Privilege Escalation

#### 5.1 Insufficient ACR (Assurance Context)

**Threat:** Attacker uses token with low assurance (ACR=basic) to access high-assurance endpoint (requires ACR=silver).

**Impact:** MEDIUM (unauthorized access to sensitive operations; depends on endpoint sensitivity).

**Likelihood:** MEDIUM-HIGH (if client misconfigures ACR requirements).

**Mitigations:**
- ✅ ACR validation on protected endpoints (e.g., `/v1/finance` requires `urn:mace:incommon:iap:silver`)
- ✅ Token issued with explicit ACR claim by Keycloak
- ✅ Sentinel verifies ACR in claims against endpoint requirement
- ✅ ACR mismatch → 403 Forbidden

**Residual Risk:** MEDIUM (depends on endpoint ACR configuration; misconfig results in weak enforcement)

---

#### 5.2 Scope Overflow

**Threat:** Token issued with fewer scopes (e.g., `read:profile` only) is used to perform higher-privilege operations (e.g., `delete:account`).

**Impact:** HIGH (privilege escalation; attacker performs unauthorized operations on behalf of user).

**Likelihood:** MEDIUM (if scope validation is missing on some endpoints).

**Mitigations:**
- ✅ Scope validation on protected endpoints (e.g., `/v1/profile` requires `read:profile`)
- ✅ Token issued with explicit `scope` claim by Keycloak
- ✅ Sentinel verifies requested scope in token scope list
- ✅ Scope mismatch → 403 Forbidden

**Residual Risk:** MEDIUM (depends on endpoint scope configuration being complete; omissions bypass check)

---

#### 5.3 Client ID Mismatch

**Threat:** Token issued for client A is used by client B (token cross-use).

**Impact:** HIGH (unauthorized client impersonates legitimate app; exfiltrates user data).

**Likelihood:** MEDIUM (if token exchange is not validated).

**Mitigations:**
- ✅ Token issued with explicit `client_id` claim by Keycloak
- ✅ Optional: Sentinel can validate client_id against requesting client (if client ID available in request context)
- ⚠️ **Current implementation:** Sentinel does not validate client_id per request (Keycloak is authoritative)

**Residual Risk:** MEDIUM (depends on Keycloak policy; Sentinel trusts Keycloak issuer)

---

### 6. Session Management

#### 6.1 Session Fixation

**Threat:** Attacker tricks user into using attacker-provided session (session ID / token).

**Impact:** MEDIUM (attacker gains access to user's session).

**Likelihood:** LOW (Sentinel does not generate session IDs; relies on Keycloak; user controls token acceptance)

**Mitigations:**
- ✅ Keycloak generates session IDs and tokens (not predictable)
- ✅ Session state tied to Keycloak user identity (attacker cannot forge)
- ✅ Sentinel validates token signature against Keycloak public key

**Residual Risk:** LOW (Keycloak handles session ID generation; Sentinel trusts issuer)

---

#### 6.2 Session Hijacking

**Threat:** Attacker intercepts session token and impersonates user.

**Impact:** CRITICAL (full account compromise).

**Likelihood:** MEDIUM (requires token interception; HTTPS mitigates but not guaranteed).

**Mitigations:**
- ✅ DPoP binding prevents token-alone usage (requires matching JWK)
- ✅ Token expiration (1h default; limits exposure window)
- ✅ Session blacklist on explicit logout (Keycloak backchannel logout)

**Residual Risk:** MEDIUM → LOW (DPoP binding + short TTL + logout option reduce risk)

---

#### 6.3 Session Timeout Bypass

**Threat:** Attacker continues using refresh token after user's session should have expired.

**Impact:** HIGH (extended unauthorized access).

**Likelihood:** MEDIUM (if refresh token TTL exceeds Keycloak session TTL).

**Mitigations:**
- ✅ Refresh token TTL aligned with Keycloak session TTL (default 28800s = 8h)
- ✅ Session blacklist on logout with TTL matching Keycloak config
- ✅ Backchannel logout from Keycloak invalidates session immediately

**Residual Risk:** MEDIUM (depends on TTL alignment; if misconfig → bypass window exists)

---

### 7. Infrastructure & Operational

#### 7.1 Redis Cache Unavailability (Fail-Open)

**Threat:** Redis is down; Sentinel falls back to accepting tokens without replay check.

**Impact:** CRITICAL (all replay protections bypassed; tokens can be reused).

**Likelihood:** MEDIUM (Redis downtime possible; datacenter issues, updates, failures).

**Mitigations:**
- ✅ Fail-closed design: If Sentinel cannot reach Redis, return 503 Service Unavailable
- ✅ Retry semantics: Caller waits and retries (standard HTTP behavior)
- ✅ Redis high availability: Sentinel cluster with replication (if deployed)
- ✅ Monitoring: Redis uptime alerts; SLA targets (99.9%)

**Residual Risk:** MEDIUM (brief Redis outages block requests; calls 503; data persistence depends on primary-replica sync)

---

#### 7.2 Clock Skew (Proof Validation)

**Threat:** Sentinel server and client have desynchronized clocks; proof JTI `iat` claim fails validation.

**Impact:** LOW (authentication failure, not security breach; user retries).

**Likelihood:** MEDIUM (NTP misconfiguration, VM clock drift in containerized environments).

**Mitigations:**
- ✅ Proof `iat` validated against server time ± 60 seconds (tolerance window)
- ✅ NTP synchronization recommended on all servers (ntpd, chrony)
- ✅ Monitoring: Clock skew alerts if drift > 5 seconds

**Residual Risk:** LOW (tolerance window handles small skew; NTP mitigates systematic drift)

---

#### 7.3 Keycloak Unavailability

**Threat:** Keycloak authorization server is down; token validation fails.

**Impact:** CRITICAL (all authentication blocked; users cannot login or refresh tokens).

**Likelihood:** MEDIUM (Keycloak outage; network partition, updates).

**Mitigations:**
- ✅ Keycloak high availability: Multiple instances, load balanced
- ✅ JWT validation uses cached public key (if Keycloak down but key was previously fetched)
- ✅ Token access period extends past brief outage
- ⚠️ **Risk:** If public key rotates during outage, new tokens cannot be validated

**Residual Risk:** MEDIUM (Keycloak is single point of failure for initial authentication; cached key mitigates brief outages)

---

#### 7.4 Log Injection / Security Event Spoofing

**Threat:** Attacker crafts request payload to emit fake security events, confusing SOC analysts.

**Impact:** MEDIUM (log noise, potential audit log manipulation if not protected).

**Likelihood:** MEDIUM (if logs include user-controlled input without sanitization).

**Mitigations:**
- ✅ Security events emitted by Sentinel code (not from request data)
- ✅ Structured logging (JSON schema) prevents log injection
- ✅ Immutable audit log (write-only append; not user-modifiable)
- ✅ Log retention: 90 days minimum (audit trail)

**Residual Risk:** LOW (events generated by code, not user input; structured format prevents injection)

---

## Threat Matrix (Likelihood × Impact)

| Threat | Likelihood | Impact | Risk | Mitigation Status |
|--------|-----------|--------|------|-------------------|
| Bearer token interception | MEDIUM | CRITICAL | HIGH | ✅ DPoP binding mitigated |
| Refresh token compromise | MEDIUM-HIGH | CRITICAL | CRITICAL | ✅ Rotation + reuse detection |
| XSS token exfiltration | HIGH | CRITICAL | CRITICAL | ⚠️ Client-side responsibility |
| Access token replay | MEDIUM | CRITICAL | HIGH | ✅ Atomic JTI + proof binding |
| DPoP proof replay | MEDIUM-HIGH | HIGH | HIGH | ✅ Nonce rotation + JTI |
| Refresh token reuse | MEDIUM | HIGH | MEDIUM-HIGH | ✅ Rotation + family tree |
| DPoP signature forgery | VERY LOW | CRITICAL | VERY LOW | ✅ Cryptographic hardness |
| JWK thumbprint collision | NEGLIGIBLE | HIGH | NEGLIGIBLE | ✅ SHA-256 hardness |
| Per-ID rate limit exhaustion | HIGH | MEDIUM | MEDIUM | ✅ Dual-partition limiter |
| Anonymous rate limit bypass | MEDIUM | MEDIUM | MEDIUM | ✅ Per-IP isolation |
| Distributed DoS | MEDIUM | CRITICAL | HIGH | ⚠️ CDN/WAF upstream |
| Insufficient ACR | MEDIUM-HIGH | MEDIUM | MEDIUM-HIGH | ✅ Endpoint validation |
| Scope overflow | MEDIUM | HIGH | MEDIUM-HIGH | ✅ Endpoint validation |
| Client ID mismatch | MEDIUM | HIGH | MEDIUM-HIGH | ⚠️ Keycloak authority |
| Session fixation | LOW | MEDIUM | LOW | ✅ Keycloak generates |
| Session hijacking | MEDIUM | CRITICAL | MEDIUM-HIGH | ✅ DPoP binding + TTL |
| Session timeout bypass | MEDIUM | HIGH | MEDIUM | ✅ TTL alignment |
| Redis unavailability | MEDIUM | CRITICAL | HIGH | ✅ Fail-closed 503 |
| Clock skew | MEDIUM | LOW | LOW | ✅ Tolerance ± 60s |
| Keycloak unavailability | MEDIUM | CRITICAL | HIGH | ⚠️ Cached key, HA required |
| Log injection | MEDIUM | MEDIUM | MEDIUM | ✅ Structured logging |

---

## Security Recommendations

### Immediate (High Priority)

1. **Client-Side XSS Protection:**
   - Implement CSP headers (block external scripts)
   - Use HttpOnly cookies for tokens (if possible)
   - Add Subresource Integrity (SRI) for CDN resources

2. **DDoS Upstream Protection:**
   - Deploy WAF/CDN (Cloudflare, AWS Shield, Azure DDoS)
   - Implement geographic IP restrictions
   - Rate limiting at edge with behavior analysis

3. **Keycloak HA:**
   - Multi-instance Keycloak cluster (3+ replicas recommended)
   - Load balancer (round-robin, health checks)
   - Public key caching in Sentinel

### Medium Term (30-60 Days)

4. **Monitoring & Alerting:**
   - Add security event dashboard (replay attempts, rate limit hits, ACR failures)
   - Alert on Redis latency > 10ms or errors > 1%
   - Alert on >10% 503 responses or JWT failures

5. **Encryption at Rest:**
   - Redis persistence encrypted (RDB snapshots)
   - Log storage encrypted (S3-SSE, Azure Storage encryption)

### Long Term (Roadmap)

6. **Hardware Security Modules (HSM):**
   - Move Keycloak signing keys to HSM for key rotation resilience
   - Consider mutual TLS (mTLS) for client-API communication

7. **Federated Token Revocation:**
   - Implement IETF Token Binding (RFC 8471) if industry adoption increases
   - Support OAUTH 2.0 Resource Indicators (RFC 8707)

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-03-15 | Initial living threat model; 20 threats identified; risk assessment |

