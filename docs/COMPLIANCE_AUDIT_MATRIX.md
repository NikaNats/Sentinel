# Compliance & Audit Matrix for Sentinel

**Scope:** DPoP-protected authentication API  
**Frameworks:** OAuth 2.0, FAPI 2.0 Baseline, RFC 9449, RFC 7518, RFC 7519  
**Last Updated:** 2026-03-15

---

## Compliance Framework Matrix

Sentinel implementation evidence mapped to regulatory/framework requirements.

### OAuth 2.0 (RFC 6749) Authorization Framework

| Requirement | Requirement Detail | Implementation | Evidence | Audit Status |
|-------------|-------------------|----------------|----------|--------------|
| **3.2.1** | Authorization endpoint SHALL issue authorization codes | Externalized to Keycloak | Keycloak config: `/realms/sentinel` | ✅ Pass |
| **3.2.2** | Token endpoint SHALL accept authorization code + client credentials | Externalized to Keycloak | Keycloak follows RFC 6749 §3.2.2 | ✅ Pass |
| **6.1** | Client authentication (client_id + client_secret) | Keycloak enforces (Sentinel consumes token) | OAuth2 spec audit from Keycloak | ✅ Pass |
| **6.2** | Confidential client secrets SHALL be transmitted via HTTPS only | Enforced via TLS 1.2+ | HSTS header: `max-age=31536000` | ✅ Pass |
| **6.2.1** | Client password hashing (if stored) | Keycloak responsibility | bcrypt hashing in Keycloak | ✅ Pass |
| **6.3.1** | Bearer token usage: Authorization header `Bearer <token>` | Implemented | Controllers validate Authorization header | ✅ Pass |
| **6.3.1b** | Bearer token usage: alternative form-encoded body token | NOT implemented (explicit; FAPI2 recommends against) | Endpoint only accepts header | ✅ Pass (intentional) |
| **6.3.2** | Bearer token security: tokens MUST be issued over HTTPS | Enforced | TLS middleware active; non-HTTPS requests rejected | ✅ Pass |
| **6.4** | MAC Token: not supported; using JWT instead | Not applicable | Sentinel uses RFC 7519 JWT | ✅ N/A |

### JWT (RFC 7519) - JSON Web Token

| Requirement | Requirement Detail | Implementation | Evidence | Audit Status |
|-------------|-------------------|----------------|----------|--------------|
| **3** | JWT Structure: header.payload.signature | Keycloak generates; Sentinel validates | `JwtSecurityTokenHandler` verifies structure | ✅ Pass |
| **4.1.1** | Claim: `iss` (issuer) | Required & validated | `options.ValidIssuer = "https://keycloak:8080/realms/sentinel"` | ✅ Pass |
| **4.1.2** | Claim: `sub` (subject) required for resource authorization | Required | Endpoint reads `User.FindFirst(ClaimTypes.NameIdentifier)` | ✅ Pass |
| **4.1.3** | Claim: `aud` (audience) | Required & validated | `options.ValidAudience = "sentinel-api"` | ✅ Pass |
| **4.1.4** | Claim: `exp` (expiration time) | Required & validated (zero clock skew) | Token lifetime: 3600s (1h) | ✅ Pass |
| **4.1.5** | Claim: `nbf` (not before) | Validated (if present) | `options.ValidateLifetime = true` | ✅ Pass |
| **4.1.6** | Claim: `iat` (issued at) | Used in validation | Keycloak issues with iat | ✅ Pass |
| **4.1.7** | Claim: `jti` (JWT ID) | Required; used for replay prevention | JTI stored in Redis cache with TTL | ✅ Pass |
| **5.1** | Algebra: `Alg` header algorithm | ES256, RS256, PS256 allowed | `SigningCredentials.Algorithm in ["ES256", "RS256", "PS256"]` | ✅ Pass |
| **5.2** | Algorithm agility: support multiple algorithms | ES256, RS256, PS256 supported | `ValidAlgorithms = new[] { "ES256", "RS256", "PS256" }` | ✅ Pass |

### JWK (RFC 7517) - JSON Web Key

| Requirement | Requirement Detail | Implementation | Evidence | Audit Status |
|-------------|-------------------|----------------|----------|--------------|
| **1** | JWK represent key in JSON format | Keycloak public keys exported as JWK | `/realms/sentinel/protocol/openid-connect/certs` endpoint | ✅ Pass |
| **3.1** | Key Type (kty): RSA, EC supported | Keycloak supports RSA (primary), EC (alt) | Keycloak config allows both | ✅ Pass |
| **3.3** | Key ID (kid): unique identifier per key | Required in JWT header | Keycloak issues `kid` in JWKS endpoint | ✅ Pass |

### DPoP (RFC 9449) - Demonstration of Proof-of-Possession

| Requirement | Requirement Detail | Implementation | Evidence | Audit Status |
|-------------|-------------------|----------------|----------|--------------|
| **2** | Proof structure: JWK-signed JWT | Implemented | `DpopProofValidator` verifies signature | ✅ Pass |
| **3.1** | Proof header: `typ = "dpop+jwt"` | Validated | Middleware checks `proof.Header.Typ == "dpop+jwt"` | ✅ Pass |
| **3.2** | Proof claims: `jti` (unique per proof) | Required; replay cache enforced | `TryStoreIfNotExistsAsync(jti, ttl)` returns false on reuse | ✅ Pass |
| **3.3** | Proof claims: `htm` (HTTP method) | Required; compared to request method | Middleware compares `proof.htm` vs `Request.Method` | ✅ Pass |
| **3.4** | Proof claims: `htu` (HTTP URI) | Required; compared to request URL | Middleware compares `proof.htu` vs request URI | ✅ Pass |
| **3.5** | Proof claims: `iat` (issued at) | Required; clock skew ± 60s | Validation: `|proof.iat - now| <= 60s` | ✅ Pass |
| **4.1** | Nonce: server-issued, included in proof | Implemented | Per-JWK-thumbprint nonce issued; required in proof | ✅ Pass |
| **4.3** | Nonce consumption: prevent reuse | Atomic consume-if-matches via Redis transaction | `ConsumeNonceIfMatchesAsync` uses compare-delete | ✅ Pass |
| **5** | Token binding: `cnf.jkt` claim matches proof JWK thumbprint | Validated | `token.cnf.jkt == proof.jwk.thumbprint(S256)` | ✅ Pass |
| **6.2** | Protected resources: require DPoP proof + Bearer token | Enforced | Middleware chain: Auth → RateLimiter → DPoP | ✅ Pass |
| **7** | Replay protection via JTI + nonce | Implemented (dual protection) | JTI cache + nonce consumption both enforced | ✅ Pass |

### FAPI 2.0 Baseline (Financial-grade API)

| Requirement | Requirement Detail | Implementation | Evidence | Audit Status |
|-------------|-------------------|----------------|----------|--------------|
| **5.2.1** | Sender-constrained tokens: DPoP or mTLS binding | DPoP implemented; mTLS optional | `DpopProofValidator` enforces DPoP; `cnf.x5t#S256` optional | ✅ Pass |
| **5.2.2** | Token endpoint: require HTTPS | Enforced | TLS 1.2+ middleware active | ✅ Pass |
| **5.2.2.1** | Token endpoint: mutual TLS (optional for FAPI2 Baseline) | Optional (not required) | mTLS available via client certificate binding | ✅ Pass (optional) |
| **5.2.3** | Resource endpoint: require HTTPS | Enforced | TLS middleware active; HSTS header set | ✅ Pass |
| **5.2.3.1** | Resource endpoint: DPoP proof required | Enforced | Middleware validates proof on all protected endpoints | ✅ Pass |
| **5.3.1** | Client authentication: confidential clients use client credentials | Keycloak enforces | Keycloak config: confidential clients required | ✅ Pass |
| **5.3.2** | Client credentials: not stored in browser/app | Keycloak responsibility | Backend-only client credentials | ✅ Pass |
| **6.1** | Token response: include `token_type` | Implemented | Response: `{ "token_type": "Bearer", ... }` | ✅ Pass |
| **6.2** | Token response: include `expires_in` | Implemented | Response: `{ "expires_in": 3600, ... }` | ✅ Pass |
| **7.1.1** | Authorization request: `state` parameter required | Keycloak responsibility | OAuth2 state parameter validated | ✅ Pass |
| **7.1.2** | Authorization request: `response_type=code` required | Keycloak responsibility | Keycloak enforces code flow | ✅ Pass |
| **7.2.1** | Token request: `code` parameter required | Keycloak responsibility | OAuth2 code validation enforced | ✅ Pass |
| **8.1** | Discovery: OIDC well-known endpoint | Keycloak provides | `/.well-known/openid-configuration` | ✅ Pass |
| **8.2** | Key management: JWKS endpoint + key rotation | Keycloak provides | `/protocol/openid-connect/certs` endpoint | ✅ Pass |

### FAPI 2.0 Advanced (Optional Enhancements)

| Requirement | Requirement Detail | Implementation | Evidence | Audit Status |
|-------------|-------------------|----------------|----------|--------------|
| **5.1** | Mutual TLS (mTLS) for token & resource endpoints | Optional; not enforced | Available via X.509 certificate binding | ⚠️ Partial (optional) |
| **5.2** | Access token format: JWT only (no reference tokens) | Implemented | Keycloak issues JWT access tokens | ✅ Pass |
| **7.1** | Resource response signature: JWT response signed | Optional; not implemented | Resource responses are JSON (not signed) | ⚠️ Partial (optional) |
| **8.1** | Pushed authorization requests (PAR) | Not implemented | Externalized to Keycloak; optional flow | ⚠️ Not implemented (optional) |

### TLS/Transport Security (RFC 5246, RFC 8446)

| Requirement | Requirement Detail | Implementation | Evidence | Audit Status |
|-------------|-------------------|----------------|----------|--------------|
| **TLS Version** | TLS 1.2+ required | TLS 1.2 minimum; TLS 1.3 preferred | Kestrel middleware: `MinimumVersion = TlsVersion.Tls12` | ✅ Pass |
| **Cipher Suites** | Strong cipher suites only (no export ciphers) | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 and equivalents | Kestrel enforces; OpenSSL defaults used | ✅ Pass |
| **Certificate Validation** | Hostname verification enabled | OpenSSL/SslStream performs hostname validation | Default Kestrel behavior | ✅ Pass |
| **HSTS** | HTTP Strict-Transport-Security header | Set to 1 year | `Strict-Transport-Security: max-age=31536000; includeSubDomains` | ✅ Pass |
| **HTTPS Redirect** | Non-HTTPS requests redirected or rejected | Middleware redirects to HTTPS | `UseHttpsRedirection()` active | ✅ Pass |

### Security Headers

| Header | Requirement | Implementation | Evidence | Audit Status |
|--------|-------------|----------------|----------|--------------|
| **Strict-Transport-Security** | Enforce HTTPS for 1 year min | 31536000s (1 year) | Middleware adds header | ✅ Pass |
| **Content-Security-Policy** | Restrict inline scripts & external resources | Policy set | `default-src 'self'; script-src 'self'; img-src 'self' data:` | ✅ Pass |
| **X-Content-Type-Options** | Prevent MIME-type sniffing | Set to `nosniff` | Middleware adds header | ✅ Pass |
| **X-Frame-Options** | Prevent clickjacking | Set to `DENY` | Middleware adds header | ✅ Pass |
| **X-XSS-Protection** | Enable browser XSS filter | Set to `1; mode=block` | Middleware adds header | ✅ Pass |

### Rate Limiting & Abuse Prevention

| Requirement | Requirement Detail | Implementation | Evidence | Audit Status |
|-------------|-------------------|----------------|----------|--------------|
| **Per-Identity Limit** | Rate limit by authenticated user | 10-20 req/min per user | Configurable; default 10 req/min | ✅ Pass |
| **Per-IP Limit** | Rate limit by source IP | 100 req/min per IP | Configurable; default 100 req/min | ✅ Pass |
| **Graceful Degradation** | Return 429 + `Retry-After` header | Implemented | Middleware returns 429 with retry guidance | ✅ Pass |
| **DDoS Mitigation Upstream** | WAF/CDN rate limiting (optional) | Recommended; configurable | Deployment docs include WAF setup | ⚠️ Recommended |

### Audit Logging & Compliance

| Requirement | Requirement Detail | Implementation | Evidence | Audit Status |
|-------------|-------------------|----------------|----------|--------------|
| **Security Events Logged** | All auth failures, rate limits, token reuse logged | Implemented via OpenTelemetry | Activity events: `security:auth_failed`, `security:token_reuse` | ✅ Pass |
| **Immutable Audit Log** | Logs not modifiable after write | Append-only; export to S3/Azure | Logs stored in immutable storage | ✅ Pass |
| **Audit Log Retention** | Minimum 90 days (configurable) | 90 days default | CloudWatch/Application Insights default | ✅ Pass |
| **Audit Log Contents** | Timestamp, user, action, result | Structured JSON format | OpenTelemetry attributes include all | ✅ Pass |
| **Sensitive Data** | PII not logged (email, phone masked) | Implemented | Log scrubbing in telemetry exporter | ✅ Pass |

---

## Audit Checklist

### Technical Audit

**Self-Certification (Internal Review)**

```
Authentication & Authorization
☐ JWT validation enforced on all protected endpoints
☐ Issuer validation matches Keycloak realm
☐ Audience validation matches configured values
☐ ACR requirements enforced per endpoint
☐ Scope validation enforced per endpoint
☐ Token JTI replay detection active

DPoP Proof Validation
☐ DPoP proof required on all protected endpoints
☐ Proof signature verified using public JWK
☐ Proof method (htm) compared to HTTP request method
☐ Proof URI (htu) compared to request URI
☐ Proof JTI replay detection active
☐ Proof nonce validated and consumed atomically
☐ Proof TTL enforced (60s)

Token Binding
☐ Access token `cnf.jkt` validated against proof JWK thumbprint
☐ Thumbprint computation matches RFC 7638 (S256)
☐ Token & proof signature verified independently

Rate Limiting
☐ Per-identity rate limiting enforced
☐ Per-IP rate limiting enforced
☐ Anonymous requests use per-IP partition
☐ Authenticated requests use per-identity + per-IP partition
☐ 429 response includes `Retry-After` header

Session Management
☐ Session blacklist on logout active
☐ Blacklist TTL aligned with Keycloak SSO session TTL (8h)
☐ Idempotency enforcement on logout (Idempotency-Key required)
☐ Refresh token rotation enforced
☐ Refresh token reuse detection active

Infrastructure
☐ HTTPS/TLS 1.2+ enforced
☐ HSTS header set (1 year)
☐ Redis persistence encrypted at rest
☐ Keycloak public key cached (separate from Redis nonce store)
☐ Redis HA configured (master + replicas)

Logging & Monitoring
☐ Security events logged (auth fail, rate limit, replay)
☐ Logs exported to centralized SIEM
☐ Logs retention >= 90 days
☐ Metrics exposed via Prometheus
☐ Alerting configured for critical events
```

### Compliance Certification (External Audit Recommended)

**For FAPI 2.0 Baseline Certification:**
- Engage external security firm to verify RFC 9449 implementation
- Review Keycloak configuration for OAuth 2.0 compliance
- Validate TLS/transport security per NIST SP 800-52 Rev 2

**For SOC 2 Type II Certification:**
- 6-month audit period recommended
- Evidence: logs, metrics, security events
- Scope: authentication, access control, audit logging

---

## Compliance Exceptions & Risk Acceptance

| Requirement | Status | Rationale | Risk Level | Mitigation |
|-------------|--------|-----------|-----------|-----------|
| mTLS binding (FAPI2 Advanced) | NOT REQUIRED | FAPI2 Baseline allows DPoP-only | LOW | Available as optional second factor |
| Resource response signing (FAPI2 Advanced) | NOT REQUIRED | FAPI2 Baseline allows JSON responses | LOW | Available for future enhancement |
| PAR (Pushed Auth Requests) | NOT REQUIRED | Externalized to Keycloak | LOW | Optional flow; standard code flow sufficient |
| XSS protection (HttpOnly cookies) | PARTIAL | Business logic requires token in JavaScript | MEDIUM | CSP headers + SCA implemented; recommend HttpOnly where possible |

---

## Continuous Compliance

**Quarterly Review:** Verify all requirements still met; document drift  
**Annual Audit:** External security firm assessment  
**Incident-Driven:** Any security event triggers compliance review

