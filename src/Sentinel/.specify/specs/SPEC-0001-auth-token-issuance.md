# Specification: User Authentication & Token Issuance

> **Spec ID**: SPEC-0001  
> **Constitution Ref**: FortressAPI Constitution v2.0.0  
> **Status**: APPROVED  
> **Template Version**: 1.0.0

---

## Meta

| Field | Value |
|---|---|
| **Spec ID** | SPEC-0001 |
| **Title** | User Authentication & Token Issuance (PAR + PKCE + DPoP) |
| **Author(s)** | IAM Architect |
| **Security Reviewer** | Security Working Group |
| **Created** | 2026-03-13 |
| **Last Updated** | 2026-03-13 |
| **Target Version** | 1.0.0 |
| **Linked Plan** | PLAN-0001 |
| **Linked Tasks** | TASK-0001 |
| **Supersedes** | N/A |
| **Compliance Scope** | NIST 800-63-3 AAL3 · FedRAMP High · FAPI 2.0 · OWASP API 2023 · FIPS 140-3 |

---

## 1. Overview

### 1.1 Problem Statement

Government employees accessing sensitive API resources require a cryptographically verifiable, phishing-resistant authentication mechanism that satisfies NIST SP 800-63-3 AAL3 assurance level. Current industry-standard flows (plain Authorization Code, ROPC, Implicit) either expose tokens in insecure channels, allow credential phishing, or fail to bind tokens to the legitimate requestor's device.

The system must issue short-lived, sender-constrained access tokens that are:
- Tied to the specific client key pair (DPoP binding) — a stolen token is useless without the private key
- Issued only after a challenge-response that cannot be replayed (PKCE S256 + PAR)
- Backed by phishing-resistant WebAuthn authentication (AAL3)
- Validated on every API request without trusting the network path

Without this, any network-level attacker or compromised intermediate service can replay or steal bearer tokens to impersonate government employees.

### 1.2 Proposed Solution Summary

Implement a complete FAPI 2.0-compliant authentication flow using Keycloak 26+ as the Authorization Server. The flow combines Pushed Authorization Requests (PAR) to protect the authorization request itself, PKCE S256 to prevent authorization code interception, DPoP (Demonstrating Proof-of-Possession) to bind tokens to the client's ephemeral key pair, and WebAuthn/Passkey as the phishing-resistant authenticator. The .NET Web API validates every incoming request by checking the JWT signature, claims, DPoP proof, and `jti` replay state before any business logic executes.

### 1.3 Out of Scope

- Social login flows (handled by a separate spec for citizen-facing portals)
- SAML 2.0 federation (separate spec for legacy integrations)
- CIBA (asynchronous approval flows — separate spec)
- Device Authorization Grant (IoT — separate spec)
- Admin impersonation flows
- Client Credentials grant (machine-to-machine — separate spec)
- User self-registration UI
- Password reset flows

---

## 2. Stakeholders & Actors

| Role | Name / Team | Responsibility |
|---|---|---|
| Feature Owner | Product Lead | Final acceptance |
| Security Reviewer | Security Working Group | Threat model + FAPI compliance sign-off |
| IAM Architect | Identity Team | Keycloak flow and token design approval |
| Data Protection Officer | Legal/Compliance | GDPR impact on session/log data |
| Operations | Platform Team | Deployment, observability, alert sign-off |

### 2.1 User / System Actors

| Actor | Type | Trust Level | Auth Mechanism |
|---|---|---|---|
| Government Employee | Human | AAL3 | WebAuthn (hardware key) + PKCE + PAR + DPoP |
| .NET Web API | Resource Server | Confidential (bearer-only) | PS256 JWT validation + DPoP verification |
| Keycloak 26+ | Authorization Server | Trusted IdP | FIPS 140-3, PS256, mTLS |
| API Gateway | Infrastructure | Internal | mTLS, JWT forwarding |
| Redis Cache | Infrastructure | Internal | mTLS, encrypted at rest |

---

## 2. Stakeholders & Actors (continued)

### 2.2 Trust Hierarchy

```
[Government Employee Browser / Desktop App]
         │  HTTPS TLS 1.3
         ▼
  [API Gateway — mTLS ingress]
         │
    ┌────┴────────────────────────────┐
    │                                 │
    ▼                                 ▼
[Keycloak 26+]                 [.NET Web API]
  PAR endpoint                  JWT validation
  Token endpoint                DPoP verification
  JWKS endpoint                 jti replay cache
  WebAuthn flow                 ACR enforcement
    │
    ▼
[FIPS HSM — signing keys]
```

---

## 3. Functional Requirements

> RFC 2119 — `SHALL` = mandatory, `SHOULD` = recommended, `MAY` = optional.

### 3.1 Authorization Request (PAR)

| ID | Requirement | Priority |
|---|---|---|
| FR-01 | The system SHALL require all authorization requests to be submitted via the PAR endpoint (`/realms/{realm}/protocol/openid-connect/ext/par/request`) before any redirect occurs | P0 |
| FR-02 | The PAR endpoint SHALL require the client to authenticate before accepting the request object | P0 |
| FR-03 | The PAR endpoint SHALL return a `request_uri` with a lifetime of ≤ 60 seconds | P0 |
| FR-04 | The `request_uri` SHALL be single-use — a second use of the same `request_uri` SHALL return an error | P0 |
| FR-05 | The PAR request SHALL include a `code_challenge` using method `S256` | P0 |
| FR-06 | The PAR request SHALL include a DPoP public key thumbprint (`dpop_jkt`) bound to the intended token | P0 |
| FR-07 | The system SHALL reject any authorization request that arrives at the authorization endpoint without a `request_uri` (i.e., direct authorization requests are forbidden) | P0 |

### 3.2 Authentication (WebAuthn AAL3)

| ID | Requirement | Priority |
|---|---|---|
| FR-08 | The system SHALL challenge the user with a FIDO2/WebAuthn authenticator as the primary credential | P0 |
| FR-09 | User Verification SHALL be set to `required` (not `preferred` or `discouraged`) — biometric or PIN confirmed locally | P0 |
| FR-10 | The system SHALL validate the authenticator's attestation against the FIDO MDS3 metadata service | P0 |
| FR-11 | The system SHALL issue an ACR claim of `acr3` in all tokens produced by WebAuthn authentication | P0 |
| FR-12 | The system SHALL support TOTP as a fallback second factor for recovery scenarios only (not as primary path) | P1 |
| FR-13 | The system SHALL enforce MFA enrollment on first login; no bypass path SHALL exist | P0 |
| FR-14 | The system SHALL lock the account after 5 consecutive failed authentication attempts within 10 minutes | P0 |

### 3.3 Token Issuance

| ID | Requirement | Priority |
|---|---|---|
| FR-15 | The token endpoint SHALL issue a DPoP-bound access token — a token issued without DPoP binding SHALL be rejected | P0 |
| FR-16 | The access token SHALL be signed with PS256 | P0 |
| FR-17 | The access token lifetime SHALL be ≤ 5 minutes | P0 |
| FR-18 | The access token SHALL contain: `sub`, `iss`, `aud`, `exp`, `iat`, `jti`, `acr`, `cnf` (DPoP thumbprint), `scope` | P0 |
| FR-19 | The access token SHALL NOT contain PII beyond the opaque `sub` identifier | P0 |
| FR-20 | The refresh token SHALL rotate on every use — reuse of a consumed refresh token SHALL invalidate the entire session | P0 |
| FR-21 | The refresh token lifetime SHALL be ≤ 8 hours | P0 |
| FR-22 | The system SHALL issue a server-generated DPoP nonce in the token response and enforce it on subsequent DPoP proofs | P0 |
| FR-23 | The ID token SHALL contain `acr`, `at_hash`, and `c_hash` | P0 |

### 3.4 Token Validation (.NET Web API)

| ID | Requirement | Priority |
|---|---|---|
| FR-24 | The API SHALL reject all requests that do not carry a valid JWT access token in the `Authorization: DPoP <token>` header | P0 |
| FR-25 | The API SHALL validate the token signature against Keycloak's JWKS endpoint, caching keys with automatic rotation | P0 |
| FR-26 | The API SHALL validate: `iss`, `aud`, `exp` (with zero clock skew), `jti` uniqueness | P0 |
| FR-27 | The API SHALL validate the DPoP proof header on every request: signature, `htm`, `htu`, `iat` freshness (≤ 60 seconds), and the server-issued nonce | P0 |
| FR-28 | The API SHALL check the `jti` claim against a Redis replay cache; a replayed `jti` SHALL result in 401 and a SIEM event | P0 |
| FR-29 | The API SHALL reject tokens with signing algorithm other than PS256 or ES256 | P0 |
| FR-30 | The API SHALL validate the `acr` claim meets the minimum required level for the requested endpoint | P0 |

### 3.5 Session & Logout

| ID | Requirement | Priority |
|---|---|---|
| FR-31 | The system SHALL support front-channel and back-channel logout | P0 |
| FR-32 | Logout SHALL invalidate all active tokens for the session (access + refresh) | P0 |
| FR-33 | The system SHALL enforce concurrent session limits per user (configurable; default 3) | P1 |
| FR-34 | The system SHALL support Global Logout — invalidating all sessions for a user across all clients | P1 |

### 3.6 API Contracts

#### PAR Endpoint (Keycloak — not .NET API)

```
POST /realms/{realm}/protocol/openid-connect/ext/par/request
Content-Type: application/x-www-form-urlencoded

Parameters:
  client_id          : string  [required]
  client_assertion   : JWT     [required — PS256 signed, for confidential clients]
  client_assertion_type : urn:ietf:params:oauth:client-assertion-type:jwt-bearer
  response_type      : code
  scope              : openid profile [required:scopes]
  redirect_uri       : string  [pre-registered only]
  state              : string  [required, ≥ 32 bytes entropy]
  nonce              : string  [required, ≥ 32 bytes entropy]
  code_challenge     : string  [required, S256]
  code_challenge_method : S256
  dpop_jkt           : string  [required — JWK thumbprint of DPoP key]

Response 201:
  { "request_uri": "urn:ietf:params:oauth:request_uri:...", "expires_in": 60 }

Error (RFC 9126):
  { "error": "invalid_request", "error_description": "..." }
```

#### Token Endpoint (Keycloak)

```
POST /realms/{realm}/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded
DPoP: <proof-JWT>

Parameters:
  grant_type     : authorization_code
  code           : string  [authorization code]
  redirect_uri   : string  [must match PAR request]
  code_verifier  : string  [PKCE verifier]
  client_id      : string
  client_assertion : JWT   [PS256]
  client_assertion_type : urn:ietf:params:oauth:client-assertion-type:jwt-bearer

Response 200:
{
  "access_token"  : "<PS256 DPoP-bound JWT>",
  "token_type"    : "DPoP",
  "expires_in"    : 300,
  "refresh_token" : "<opaque>",
  "id_token"      : "<PS256 JWT>",
  "scope"         : "openid profile",
  "DPoP-Nonce"    : "<server-nonce>"
}

Error (RFC 6749):
  HTTP 400 { "error": "...", "error_description": "..." }
```

#### Protected API Endpoint (example — .NET Web API)

```
GET /v1/profile
Authorization: DPoP <access_token>
DPoP: <proof-JWT>

Response 200:
{
  "sub"         : "<opaque UUID>",
  "displayName" : "string",
  "roles"       : ["string"]
}

Response 401 (missing/invalid token):
{
  "type"          : "/errors/unauthorized",
  "title"         : "Authentication required",
  "status"        : 401,
  "correlationId" : "uuid"
}

Response 401 (DPoP invalid):
WWW-Authenticate: DPoP error="invalid_dpop_proof", algs="PS256 ES256"
{
  "type"          : "/errors/invalid-dpop-proof",
  "title"         : "DPoP proof validation failed",
  "status"        : 401,
  "correlationId" : "uuid"
}
```

### 3.7 Data Model

```
Entity: UserSession (logical — stored in Keycloak + Redis)
Fields:
  - sessionId      : UUID v4      [PK — Keycloak session ID]
  - sub            : UUID v4      [opaque user identifier]
  - clientId       : string       [Keycloak client ID]
  - acr            : string       [acr1|acr2|acr3]
  - dpopJkt        : string       [JWK thumbprint of bound key]
  - issuedAt       : ISO8601 UTC  [immutable]
  - expiresAt      : ISO8601 UTC  [absolute session expiry]
  - lastActivity   : ISO8601 UTC  [updated on refresh]
  - ipAddressHash  : string       [SHA-256 of client IP — for audit only]
  - userAgentHash  : string       [SHA-256 of User-Agent — for audit only]

Entity: JtiReplayRecord (Redis — ephemeral)
Fields:
  - key     : "replay:jti:{jti-value}"
  - value   : ""   [presence is the signal — no value needed]
  - ttl     : int  [seconds — set to remaining token lifetime]

Classification: CONFIDENTIAL
PII Fields: none (sub is opaque; IP/UA are hashed)
Retention: Session duration + 30 days audit log
```

---

## 4. Non-Functional Requirements

### 4.1 Security Requirements

| Requirement | Specification | Constitution Ref |
|---|---|---|
| Authentication | PAR + Auth Code + PKCE S256 + WebAuthn (AAL3) + DPoP | §II.1, §II.3, §II.4 |
| Token Signing | PS256 only — RS256/HS256 blocked by Client Policy | §IV.1 |
| Token Binding | DPoP (`cnf.jkt`) — token useless without client private key | §II.4 |
| Token Lifetime | Access ≤ 5 min, Refresh ≤ 8 h + mandatory rotation | §II.4 |
| MFA | WebAuthn hardware key, UV=required, MDS3 attestation | §II.3 |
| Replay Prevention | `jti` Redis cache, DPoP nonce, PKCE single-use verifier | §III.1 |
| Transport | TLS 1.3 only, HSTS preload, mTLS internal | §III.4 |
| Algorithm Restriction | PS256/ES256 — enforced by Client Policy + middleware allowlist | §IV.1 |
| FIPS Compliance | Bouncy Castle FIPS in Keycloak; FIPS-approved .NET algos | §IV.3 |
| Brute Force | Account lock after 5 failures / 10 min | §II.3 FR-14 |
| Audit | All token issuance + auth failures to immutable SIEM | §VI.3 |

### 4.2 Performance Requirements

| Metric | Target | Measurement |
|---|---|---|
| PAR response p99 | ≤ 200 ms | OTel trace |
| Token issuance p99 | ≤ 300 ms (includes WebAuthn round-trip excluded) | OTel trace |
| API token validation p99 | ≤ 10 ms (cached JWKS, Redis hit) | OTel trace |
| `jti` Redis SET/GET | ≤ 2 ms p99 | Redis latency metric |
| Availability | 99.99% (Keycloak clustered) | SLO dashboard |

### 4.3 Observability Requirements

- Distributed trace spans: PAR request, token issuance, DPoP validation, `jti` cache check
- Metrics: `auth_requests_total{outcome}`, `token_issued_total{acr}`, `dpop_failures_total{reason}`, `jti_replay_total`
- Structured log fields: `correlationId`, `sub`, `clientId`, `acr`, `action`, `outcome`, `ipHash`
- SIEM alerts: auth failure spikes, token replay detection, algorithm downgrade attempt

---

## 5. Threat Model

### 5.1 Assets & Trust Boundaries

```
Assets:
  - Authorization Code:        HIGH — exchangeable for tokens
  - Access Token:              HIGH — grants API access
  - Refresh Token:             CRITICAL — long-lived session credential
  - DPoP Private Key:          CRITICAL — binds tokens to client
  - WebAuthn Credential:       CRITICAL — user authentication factor
  - Keycloak Signing Key:      CRITICAL — trust anchor for all tokens
  - jti Replay Cache (Redis):  HIGH — integrity required for replay prevention

Trust Boundaries:
  - Internet → API Gateway          (TLS 1.3 terminates here)
  - API Gateway → Keycloak          (mTLS)
  - API Gateway → .NET Web API      (mTLS, JWT forwarded)
  - .NET Web API → Redis            (mTLS, encrypted)
  - .NET Web API → Keycloak JWKS    (mTLS, pinned)
  - Keycloak → HSM                  (PKCS#11, internal only)
```

### 5.2 STRIDE Analysis

| ID | Threat | Category | Component | DREAD | Mitigation | Status |
|---|---|---|---|---|---|---|
| T-01 | Attacker intercepts authorization code in redirect URI | Spoofing | Auth Code | 8 | PKCE S256 — code verifier never leaves client; interception produces unusable code | ✅ Mitigated |
| T-02 | Attacker replays stolen access token | Repudiation | Access Token | 9 | DPoP binding — token tied to ephemeral key pair; useless without private key | ✅ Mitigated |
| T-03 | Attacker replays used `jti` before expiry | Repudiation | API Middleware | 8 | Redis `jti` replay cache — first use stores `jti`; second use blocked | ✅ Mitigated |
| T-04 | Phishing attack captures WebAuthn credential | Spoofing | WebAuthn | 9 | WebAuthn is origin-bound — credential unusable on attacker's domain | ✅ Mitigated |
| T-05 | Attacker injects `RS256` token to exploit algorithm confusion | Tampering | JWT Validation | 9 | Algorithm allowlist in middleware (`PS256`, `ES256` only) + Client Policy | ✅ Mitigated |
| T-06 | Attacker sends authorization request directly (bypassing PAR) | Tampering | Auth Endpoint | 8 | `require_pushed_authorization_requests=true` — direct requests rejected | ✅ Mitigated |
| T-07 | Attacker brute-forces user credentials | Elevation | Auth Flow | 7 | Account lockout (5 failures / 10 min) + WebAuthn (no password to brute-force) | ✅ Mitigated |
| T-08 | Stolen refresh token used to maintain unauthorized session | Elevation | Refresh Token | 9 | Refresh token rotation + reuse detection — consumed token reuse invalidates session | ✅ Mitigated |
| T-09 | JWKS endpoint returns attacker-controlled key | Spoofing | JWKS | 9 | JWKS URL pinned in config; mTLS to Keycloak; metadata endpoint HTTPS only | ✅ Mitigated |
| T-10 | DPoP proof replay across different endpoints | Repudiation | DPoP Proof | 7 | `htm` + `htu` claim validation in proof — proof scoped to exact method + URL | ✅ Mitigated |
| T-11 | Redis `jti` cache poisoned / cleared by attacker | Tampering | Redis | 7 | Redis mTLS + auth; network policy restricts access to API pods only | ✅ Mitigated |
| T-12 | Keycloak admin console exposed to internet | Elevation | Keycloak Admin | 10 | Admin console on internal network only; no public ingress; mTLS required | ✅ Mitigated |
| T-13 | Token issued with excessive lifetime | Elevation | Token Config | 6 | Client Policy enforces max lifetime; realm-level cap non-overridable by client | ✅ Mitigated |
| T-14 | Attacker downgrades DPoP to plain Bearer via request manipulation | Tampering | API Middleware | 8 | DPoP middleware rejects `Authorization: Bearer` on DPoP-required endpoints | ✅ Mitigated |

### 5.3 OWASP API Top 10 (2023) Coverage

| Risk | Applicable | Mitigation |
|---|---|---|
| API1 — BOLA | No (auth flow, not data resource) | N/A for this spec |
| API2 — Broken Authentication | YES | FAPI 2.0 full stack — PAR + PKCE + DPoP + WebAuthn |
| API3 — Broken Property Level Auth | Partial | Token claims allow-list; no PII in tokens |
| API4 — Unrestricted Resource Consumption | YES | Rate limiting on PAR + token endpoints; brute-force lockout |
| API5 — Broken Function Level Auth | YES | ACR enforcement per endpoint; scope validation |
| API6 — Unrestricted Access to Sensitive Flows | YES | PAR single-use; PKCE single-use; `request_uri` TTL |
| API7 — SSRF | No | No outbound requests from auth flow |
| API8 — Security Misconfiguration | YES | Client Policies enforce invariants; CI IaC scan |
| API9 — Improper Inventory Management | YES | All endpoints in OpenAPI; route-audit CI gate |
| API10 — Unsafe API Consumption | YES | JWKS pinned; Keycloak metadata validated via mTLS |

### 5.4 Residual Risks

| Risk | Likelihood | Impact | Accepted By | Review Date |
|---|---|---|---|---|
| Hardware security key lost by employee | Low | Medium | Security WG | 2026-09-13 |
| Redis cache unavailable — `jti` replay check fails open or closed | Low | High | Security WG | 2026-09-13 |

> Decision on Redis failure mode: **fail closed** — if Redis is unavailable, the API returns 503. Replay check cannot be skipped.

---

## 6. Keycloak Configuration

### 6.1 Client Configuration

```json
{
  "clientId": "fortressapi-gov-client",
  "name": "FortressAPI Government Client",
  "description": "FAPI 2.0 compliant government employee client",
  "clientAuthenticatorType": "client-jwt",
  "protocol": "openid-connect",
  "publicClient": false,
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": false,
  "implicitFlowEnabled": false,
  "serviceAccountsEnabled": false,
  "redirectUris": ["https://app.agency.gov/callback"],
  "webOrigins": ["https://app.agency.gov"],
  "attributes": {
    "pkce.code.challenge.method": "S256",
    "dpop.bound.access.tokens": "true",
    "require.pushed.authorization.requests": "true",
    "token.endpoint.auth.signing.alg": "PS256",
    "id.token.signed.response.alg": "PS256",
    "access.token.signed.response.alg": "PS256",
    "access.token.lifespan": "300",
    "client.session.idle.timeout": "28800",
    "client.session.max.lifespan": "28800",
    "use.refresh.tokens": "true",
    "refresh.token.max.reuse": "0",
    "backchannel.logout.session.required": "true",
    "backchannel.logout.revoke.offline.tokens": "true",
    "post.logout.redirect.uris": "https://app.agency.gov/logout-complete"
  }
}
```

### 6.2 Scopes Required

| Scope | Purpose | Granted To |
|---|---|---|
| `openid` | OIDC baseline | All clients |
| `profile` | Display name, preferred_username | Authenticated employees |
| `roles` | Realm/client roles in token | All clients |
| `offline_access` | Refresh tokens | Gov employee client only |

### 6.3 Authentication Flow — Government AAL3

```
Flow Name: government-aal3-browser
Type: Browser

Steps:
  1. Username / Email identification form
  2. WebAuthn Authenticator (REQUIRED)
     - User Verification: required
     - Attestation: direct
     - User verification timeout: 300 seconds
  3. [Conditional] TOTP — only if WebAuthn fails 3 times (recovery path)
  4. Post-authentication: ACR = "acr3" mapped to this flow

ACR Mapping:
  acr3 → government-aal3-browser (WebAuthn UV=required)
  acr2 → standard-mfa-browser   (password + TOTP)
  acr1 → (disabled for this realm)

Step-Up Trigger:
  Any scope in { admin:*, pii:read, finance:write } → requires acr3 re-challenge
  Step-up max validity: 15 minutes
```

---

## 7. Acceptance Criteria

### 7.1 Functional

- [ ] FR-01–07: PAR flow — client cannot initiate auth without PAR; `request_uri` is single-use and expires in 60s
- [ ] FR-08–14: WebAuthn AAL3 — login without hardware key fails; `acr3` present in tokens; account locks after 5 failures
- [ ] FR-15–23: Token issuance — DPoP-bound PS256 tokens, ≤5 min lifetime, `jti` unique, `cnf` claim present
- [ ] FR-24–30: API validation — all 7 validation checks enforced independently (each one tested in isolation)
- [ ] FR-31–34: Logout — front-channel + back-channel tested; all tokens invalidated

### 7.2 Security Scenarios

- [ ] T-01: Intercepted auth code without verifier → token endpoint rejects
- [ ] T-02: Replayed access token without DPoP key → API rejects
- [ ] T-03: Second request with same `jti` → 401 + SIEM event fired
- [ ] T-05: RS256 token submitted → rejected before any claim check
- [ ] T-06: Direct authorization request (no PAR) → Keycloak rejects
- [ ] T-08: Consumed refresh token reused → session invalidated
- [ ] T-14: `Authorization: Bearer` on DPoP endpoint → 401

### 7.3 Non-Functional

- [ ] API token validation p99 ≤ 10 ms under 500 rps sustained load
- [ ] Redis unavailable → API returns 503 (fail-closed verified)
- [ ] OTel traces visible end-to-end for full auth flow
- [ ] SIEM receives `AUTH_SUCCESS`, `AUTH_FAILURE`, `TOKEN_REPLAY` events

---

## 8. Data Protection & Privacy

| Question | Answer |
|---|---|
| Does this feature process PII? | Minimal — `sub` is opaque UUID; IP/UA hashed for audit |
| Legal basis | Legal obligation (government security mandate) |
| PII fields in tokens | None — `sub` is opaque |
| PII in logs | None — IP and UA are SHA-256 hashed before logging |
| Retention | Session: 8 hours active; Audit logs: 7 years |
| Cross-border transfer | No |
| DPIA required | No (no new PII categories; existing legal basis) |

---

## 9. Open Questions (Resolved)

| # | Question | Resolution |
|---|---|---|
| 1 | Redis failure mode: fail-open or fail-closed? | **Fail-closed** — 503 returned; replay check is safety-critical |
| 2 | TOTP as fallback — how many WebAuthn failures before TOTP offered? | **3 consecutive failures** within the same session |
| 3 | DPoP nonce rotation frequency? | **Per token response** — new nonce issued with every access/refresh token |

---

## References

- [FortressAPI Constitution v2.0.0](../constitution.md)
- [NIST SP 800-63B — AAL3 requirements](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [RFC 9449 — DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 9126 — PAR](https://datatracker.ietf.org/doc/html/rfc9126)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-2_0-security-profile.html)
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
