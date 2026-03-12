# SentinelAPI Constitution v2.0.0

**Maximum-Security API Constitution**  
*Government-Grade · NIST 800-63-3 · FedRAMP High · GDPR · FAPI 2.0 · Zero Trust*  
*Stack: .NET 9+ (forward-compatible) · Keycloak 26+ · Web API only*

---

## Preamble

This Constitution defines the **immutable security baseline** for all systems under SentinelAPI governance. It is architected for government-grade deployment under NIST SP 800-63-3, FedRAMP High, GDPR, and FAPI 2.0. Every principle is binding. Every listed Keycloak feature that increases security posture **must** be activated. No exception is permitted without the process defined in the Governance section.

---

## Part I — Foundational Principles

### I.1 Zero Trust Architecture (ZTA)
Every request — regardless of origin, network position, or claimed identity — is treated as hostile until proven otherwise. This is non-negotiable.

- **Default-deny** at every layer (network, gateway, application, data)
- **Never trust the network** — mTLS between all internal services
- **Never trust a header** — all claims verified cryptographically at each hop
- **Assume breach** — every component is designed to limit blast radius post-compromise
- **Explicit verification** — identity, device posture, and context validated on every request
- **Least privilege access** — minimal scopes, roles, and permissions; revoked immediately on scope change

### I.2 Secure-by-Design
Security is not retrofitted — it is the starting constraint, not the ending review.

- All features begin with a mandatory **STRIDE + DREAD threat model**
- Every architectural decision documents its threat mitigation rationale
- No feature ships without a corresponding security test suite
- **YAGNI + KISS** — smaller attack surface is always preferred over feature richness

### I.3 Compliance Baseline (ALL simultaneously enforced)

| Standard | Scope |
|---|---|
| NIST SP 800-63-3 / AAL2–AAL3 | Authentication Assurance |
| NIST SP 800-207 | Zero Trust Architecture |
| FedRAMP High | Cloud Security Controls |
| OWASP API Security Top 10 (2023) | API Threat Prevention |
| FAPI 2.0 Security Profile | OAuth/OIDC Hardening |
| GDPR / Data Protection | EU Data Handling |
| FIPS 140-3 | Cryptographic Modules |
| RFC 9700 (OAuth 2.0 Security BCP) | OAuth Best Current Practice |

---

## Part II — Identity Platform: Keycloak Configuration (ALL features active)

Keycloak is the **sole Authorization Server and Identity Provider**. All features below are **mandatory** unless explicitly marked `[conditional]`.

### II.1 Core Identity Protocols

#### Single Sign-On (SSO) & Single Sign-Out
- SSO enabled across all realm applications — browser and native clients
- **Front-channel logout** and **back-channel logout** both configured
- Global logout (`/logout`) invalidates **all** sessions across all clients simultaneously
- Session idle and max lifespan strictly bounded (see §IV.3)
- **Logout All Sessions** endpoint exposed only to admin roles via mTLS

#### OpenID Connect (OIDC) — Full Activation
- Discovery document (`/.well-known/openid-configuration`) publicly exposed on HTTPS only
- **Dynamic Client Registration** disabled in production; pre-registered clients only
- `id_token`, `userinfo`, `introspect`, and `token` endpoints all require valid bearer proofs
- `at_hash` and `c_hash` mandatory in ID tokens
- **OIDC Logout** (RP-Initiated Logout + Session Management) enforced

#### OAuth 2.0
- **Authorization Code Flow + PKCE S256** — the only interactive grant permitted
- **Client Credentials** — permitted only for server-to-server with mTLS client authentication
- **Device Authorization Flow** — for IoT/constrained devices with enrollment approval gate
- **Token Exchange** (standard + external-to-internal) — scoped and audited; requires explicit policy
- **JWT Authorization Grant** (RFC 7523) — preview active; used for service mesh inter-service auth
- **Implicit, ROPC, and plain PKCE** grants — **permanently disabled**

#### SAML 2.0
- Keycloak acts as **SAML IdP** for legacy government integrations where OIDC is unavailable
- **Signed assertions** (RSA-SHA256 minimum, PS256 preferred) and **encrypted assertions** mandatory
- **POST binding only** — redirect binding disabled for sensitive realms
- Metadata exchange via pre-shared, pinned metadata files — no dynamic resolution

#### Client Initiated Backchannel Authentication (CIBA)
- Enabled for **asynchronous step-up authentication** scenarios (e.g., high-value transaction approval)
- Push mode only — polling mode disabled
- Binding message mandatory; expiry ≤ 120 seconds

#### Pushed Authorization Requests (PAR)
- **Mandatory for all clients** — `require_pushed_authorization_requests = true` realm-wide
- PAR endpoint requires client authentication before accepting request objects
- `request_uri` single-use, expires in ≤ 60 seconds

### II.2 Identity Brokering & Federation

#### Identity Brokering (External IdPs)
- External OIDC/SAML providers brokered only if they meet **equivalent AAL2+ assurance**
- First-login flow enforces account linking audit log entry
- **Trust elevation** step-up required when brokered sessions access sensitive resources
- No automatic account merging — manual identity linking requires admin approval `[conditional: high-assurance realms]`

#### Social Login `[conditional]`
- Permitted only for **non-sensitive citizen-facing portals** (not government employee systems)
- Every social login session is bounded to a separate, lower-privilege realm
- MFA step-up mandatory before accessing any non-public resource

#### User Federation — LDAP / Active Directory
- Sync-only federation: Keycloak does **not** write back to AD unless explicitly required
- **LDAPS (LDAP over TLS 1.3)** only — no plaintext LDAP
- Periodic full sync + event-driven delta sync
- **Kerberos / SPNEGO bridge** active for workstation SSO in AD-joined environments
  - SPNEGO negotiation constrained to internal Kerberos realm
  - Cross-realm trust disabled unless explicitly approved and threat-modeled

### II.3 Authentication Security

#### Multi-Factor Authentication (MFA) — Mandatory
- **FIDO2 / WebAuthn / Passkeys** — primary strong factor (AAL3-capable with hardware security keys)
  - Conditional UI enabled — passkey autofill on supported browsers
  - Resident keys (discoverable credentials) preferred
  - User verification (`required`) — not just user presence
- **TOTP (HMAC-SHA-1, 6-digit, 30s)** — secondary factor; hardware OATH tokens accepted
- **Recovery codes** — generated at enrollment, encrypted at rest, single-use
- **SMS / email OTP** — **prohibited** for government employee auth (phishing risk); `[conditional]` for low-assurance citizen flows only
- MFA enrollment is mandatory on first login; cannot be bypassed or delegated away

#### Step-Up Authentication
- Keycloak **Step-Up Authentication** flow enforced before:
  - Accessing sensitive API scopes (`finance:write`, `admin:*`, `pii:read`)
  - Initiating token exchange to elevated service accounts
  - CIBA-triggered approvals
- Step-up re-challenges the user even within an active session
- Step-up ACR values (`acr_values`) validated in access tokens by the resource server

#### Passkeys & WebAuthn
- Resident passkeys synced across authenticator apps `[conditional: device-bound only in AAL3 scenarios]`
- Attestation verification enabled; `direct` attestation format required for government hardware keys
- FIDO metadata service (MDS3) integration for authenticator certification validation

### II.4 Token Security (FAPI 2.0 Grade)

#### Token Configuration (realm-wide, non-overridable by clients)
- Access token lifespan: **≤ 5 minutes** (government) / ≤ 15 minutes (standard)
- Refresh token lifespan: **≤ 8 hours**, **rotation mandatory** (each use issues a new token)
- Refresh token reuse detection: **sender-constrained** — refresh token theft detection active
- ID token: signed **PS256** only; encrypted with **RSA-OAEP-256 + A256GCM** for sensitive flows
- Access token format: **JWT (signed PS256 / ES256)**; opaque tokens `[conditional: legacy integrations]`

#### DPoP — Demonstrating Proof-of-Possession
- **Mandatory on all public clients** and all SPAs
- DPoP nonce challenge enabled — server-issued nonces, single-use
- DPoP proofs verified at introspection and resource server level
- Token binding via `jkt` (JWK thumbprint) claim validated end-to-end

#### Token Claims Hardening
- `aud` (audience) claim: strictly validated — tokens rejected if `aud` doesn't match resource server identifier
- `iss` (issuer) claim: pinned, validated against well-known JWKS
- `jti` (JWT ID): mandatory — used for token replay detection (stored in distributed cache, TTL = token lifetime)
- `acr` claim: mandatory — validated by resource server against required assurance level
- `cnf` (confirmation) claim: mandatory for DPoP-bound tokens
- No custom claims containing PII unless request includes `claims` parameter with explicit consent scope

#### Signing Algorithms
- **Permitted**: PS256, PS384, PS512, ES256, ES384, ES512
- **Prohibited**: RS256, HS256, HS384, HS512, none — blocked at realm Client Policy level
- JWKS rotation: automated with 6-hour overlap window

#### Client Secret Rotation
- Client secret rotation policy active: maximum secret age = 90 days
- Rotation event triggers audit log entry and security alert
- Dual-secret overlap window: 24 hours maximum

### II.5 Authorization

#### Role-Based Access Control (RBAC)
- **Realm roles** for cross-application entitlements
- **Client roles** for application-specific permissions
- **Composite roles** used sparingly — fully documented, threat-modeled
- No role assigned without corresponding least-privilege justification

#### Fine-Grained Authorization Services (UMA 2.0)
- **Resource Server registration** for every .NET Web API
- Permission policies: **resource-based + scope-based + attribute-based + time-based conditions**
- UMA 2.0 flows for user-managed access delegation (citizen data sharing)
- **Broken Object Level Authorization (BOLA)** — every resource endpoint backed by a Keycloak resource with explicit scope policy; no implicit access
- **Broken Property Level Authorization** — explicit allow-list of returnable properties enforced at policy layer
- Policy evaluation: **Unanimous strategy** — all matching policies must permit

#### Fine-Grained Admin Permissions (v2)
- Keycloak admin actions scoped per-realm, per-resource-type
- No admin has global realm admin rights in production — scoped admin roles only
- Admin actions logged to immutable audit trail

#### Dynamic Scopes
- Scopes parameterized where needed (e.g., `resource:read:{resourceId}`) — enforced via policy
- Scope whitelist enforced at Client Policy level — undeclared scopes rejected

### II.6 Session & User Management

#### Session Security
- **Persistent User Sessions** — survive Keycloak restart; stored encrypted in distributed cache
- Session binding: IP stickiness `[optional]` — device fingerprint preferred
- Concurrent session limit: configurable per client / role (default: 3 sessions max per user)
- Session idle timeout: **15 minutes** (privileged clients) / **30 minutes** (standard)
- Absolute session max: **8 hours**

#### Client Policies & Client Profiles
- Realm-wide **Client Policies** enforce security invariants on every registered client:
  - `pkce-enforcer` — S256 only
  - `dpop-enforcer` — mandatory for public clients
  - `par-enforcer` — mandatory for all
  - `secure-signing-algorithm` — PS256/ES256 minimum
  - `secure-request-object` — signed request objects for sensitive clients
  - `holder-of-key-enforcer` — mTLS or DPoP binding required
- Client Profiles versioned and stored in Git — any deviation triggers CI failure

#### Client Types
- **Public clients**: Browser SPAs, mobile apps — DPoP + PKCE + PAR mandatory
- **Confidential clients**: Server-side — mTLS client authentication mandatory; no client_secret over the wire
- **Bearer-only clients**: Resource servers — no interactive flows; token introspection only

#### Impersonation
- Admin impersonation: **disabled by default** in production
- Enabled only with dual-approval workflow, time-boxed (≤ 2 hours), fully audited
- Impersonation sessions watermarked in token claims (`act` claim, RFC 8693)

### II.7 Multi-Tenancy & Organizations

#### Organizations (CIAM / B2B2C)
- Each government agency / tenant mapped to a Keycloak **Organization** within a shared realm `[conditional: multi-tenant deployments]`
- Organization-level identity provider brokering scoped per org
- Cross-organization data access requires explicit, audited token exchange
- Organization membership managed via federated provisioning (SCIM 2.0 preferred)

### II.8 Observability & Operations

#### OpenTelemetry Integration
- Keycloak emits **traces, metrics, and logs** via OpenTelemetry collector
- Trace propagation: W3C `traceparent` header — correlation IDs flow end-to-end from Keycloak → .NET API → downstream
- **User Event Metrics**: login, logout, token-issue, token-refresh, failed-auth counters exported to Prometheus
- **Logging MDC** (Mapped Diagnostic Context): `userId`, `sessionId`, `clientId`, `realmId`, `requestId` attached to every log line

#### Security Event Logging
- All security-relevant Keycloak events streamed to **immutable SIEM** (Splunk / Elasticsearch with write-once index):
  - `LOGIN`, `LOGIN_ERROR`, `LOGOUT`, `TOKEN_EXCHANGE`, `IMPERSONATE`, `REGISTER`, `UPDATE_PASSWORD`, `CLIENT_UPDATE`, `ADMIN_*`
- Retention: **7 years** (FedRAMP requirement)
- No PII in event payloads beyond opaque identifiers — tokenized references only

### II.9 Specialized & Hardening Features

#### FIPS Mode
- Keycloak FIPS 140-3 mode **enabled** — only FIPS-validated cryptographic providers active
- Bouncy Castle FIPS provider for JVM
- Verified at startup; Keycloak refuses to start if FIPS validation fails

#### Hostname v2
- Strict hostname configuration — Keycloak rejects requests not matching configured hostname
- Reverse proxy / edge TLS termination via Hostname v2 provider
- `proxy-headers` set to `xforwarded` only if reverse proxy is trusted; otherwise `none`

#### Kubernetes Integration
- Keycloak service accounts mapped to Kubernetes service account tokens for workload identity
- Pod-level mTLS via service mesh (Istio / Linkerd) — Keycloak validates SPIFFE/SVID certificates

#### OID4VC / Verifiable Credentials (Preview)
- Activated for **digital identity credential issuance** scenarios `[conditional: digital ID programs]`
- Credential format: **SD-JWT VC** (Selective Disclosure JWT)
- Holder binding mandatory

#### SPI Extensibility
- Custom SPIs (authenticators, event listeners, mappers, storage providers) subject to same code review and threat modeling requirements as application code
- JavaScript providers: **disabled** in production (security risk)
- All custom SPIs version-pinned and reproducibly built

#### Clusterless Mode
- Single-node deployments use **clusterless mode** (no Infinispan dependency) for dev/staging only
- Production: **clustered Infinispan** with encrypted inter-node communication (JGroups encryption stack)

---

## Part III — .NET Web API Security Layer

### III.1 Authentication Middleware
- `Microsoft.AspNetCore.Authentication.JwtBearer` configured with:
  - Authority: Keycloak realm URL (HTTPS only)
  - JWKS auto-rotation via metadata endpoint
  - `ValidateIssuer = true`, `ValidateAudience = true`, `ValidateLifetime = true`
  - `ClockSkew = TimeSpan.Zero` — no tolerance for expired tokens
  - `RequireHttpsMetadata = true`
- **DPoP validation middleware**: custom middleware validates `DPoP` proof header on every request before JWT bearer validation
- **Token replay cache**: `jti` checked against distributed Redis cache (TTL = access token lifetime)

### III.2 Authorization
- Keycloak Authorization Services integrated via **UMA 2.0 ticket flow** or **token introspection**
- `[Authorize(Policy = "resource:scope")]` on every endpoint — no implicit public endpoints
- **Resource-based authorization**: every object-level access validated via Keycloak resource policy
- **Property-level authorization**: response DTOs defined with explicit `[AllowedInResponse]` attributes — auto-stripping of unauthorized properties
- ACR validation: middleware rejects tokens with insufficient `acr` for the requested operation

### III.3 Input Validation & Output Encoding
- **FluentValidation** for all request models — schema + type + range + format
- No raw user input reaches: SQL queries (parameterized EF Core only), shell commands (none), logs (structured only)
- **Mass assignment prevention**: DTOs never mapped directly from request body to domain models — explicit mappers only
- Output: JSON only, UTF-8, `Content-Type: application/json; charset=utf-8`
- **No stack traces** in error responses — generic `ProblemDetails` (RFC 7807) with correlation ID only

### III.4 Transport Security
- **TLS 1.3 only** — TLS 1.0/1.1/1.2 disabled at listener level
- **HSTS**: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
- **Certificate Transparency** (CT) logs validated at TLS handshake (if CT enforcement is available at load balancer)
- **mTLS** on all internal service-to-service communication — client certificates from internal PKI (SPIFFE/SVID)

### III.5 API Security Headers
Every response must include:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
Cache-Control: no-store
Pragma: no-cache
```

### III.6 Rate Limiting & Abuse Prevention
- **Token Bucket** rate limiting per `sub` (user), per client_id, per IP
- Separate, stricter limits on authentication endpoints (PAR, token, introspect)
- **Adaptive throttling**: anomaly detected → rate reduced → alert triggered → account flagged for review
- **Brute-force protection** mirrored from Keycloak (permanent lockout after configurable failures) + API-layer enforcement

### III.7 Structured Logging & Correlation
- **Serilog** with JSON sink — every log line includes:
  - `CorrelationId` (W3C `traceparent`), `UserId` (opaque), `ClientId`, `RequestPath`, `StatusCode`, `DurationMs`
- **No PII in logs**: user-identifying data replaced with opaque `sub` from token
- Logs shipped to SIEM in real-time — local disk as buffer only, never as primary store
- Log integrity: HMAC-signed log batches — tampering detectable at SIEM ingestion

### III.8 Secret & Configuration Management
- **No secrets in `appsettings.json`, `.env`, or source code** — ever
- Secrets sourced from: **Azure Key Vault / HashiCorp Vault / AWS Secrets Manager** via managed identity
- `.NET` `IConfiguration` backed by vault provider — secrets injected at startup, rotated without restart
- Connection strings, signing keys, and client credentials all vault-managed

---

## Part IV — Cryptographic Standards

### IV.1 Algorithms (ALL contexts)

| Purpose | Permitted | Prohibited |
|---|---|---|
| JWT Signing | PS256, PS384, PS512, ES256, ES384, ES512 | RS256, HS256, HS512, `none` |
| JWT Encryption | RSA-OAEP-256 + A256GCM, ECDH-ES + A256GCM | RSA-PKCS1, A128CBC-HS256 |
| TLS | TLS 1.3 (AES-256-GCM, ChaCha20-Poly1305) | TLS ≤ 1.2, RC4, 3DES |
| Password Hashing | Argon2id (m=65536, t=3, p=4), bcrypt (cost≥12) | MD5, SHA-1, plain SHA-256 for passwords |
| Symmetric Encryption | AES-256-GCM, ChaCha20-Poly1305 | AES-128-ECB, DES |
| Key Derivation | HKDF-SHA256, PBKDF2-SHA256 (≥600,000 iter) | PBKDF2-SHA1 |
| HMAC | HMAC-SHA256 minimum | HMAC-MD5, HMAC-SHA1 |

### IV.2 Key Management
- All cryptographic keys managed in **FIPS 140-3 Level 3 HSM** in production
- Key rotation schedule: signing keys ≤ 90 days, encryption keys ≤ 365 days
- Retired keys: grace period (for token validation) = 1 × max token lifetime, then destroyed
- JWKS endpoint serves only active + grace-period public keys
- **No private key export** — all signing operations performed inside HSM

### IV.3 FIPS Compliance
- .NET: `System.Security.Cryptography.CryptographicOperations` restricted to FIPS-approved algorithms
- `AppContext.SetSwitch("Switch.System.Security.Cryptography.UseLegacyFipsThrow", false)` — FIPS enforcement active
- Keycloak FIPS mode (see §II.9) aligned

---

## Part V — Infrastructure & Deployment Security

### V.1 Container Security
- **Minimal base images**: `mcr.microsoft.com/dotnet/aspnet:9.0-jammy-chiseled` (rootless, distroless)
- **Non-root user** in all containers (`USER app`)
- **Read-only root filesystem** — writable mounts only for `/tmp` and explicit data directories
- No `privileged: true`, no `hostNetwork: true`, no `hostPID: true`
- **Seccomp profile**: `RuntimeDefault` or custom restricted profile
- **AppArmor / SELinux** profiles enforced

### V.2 Supply Chain Security
- All container images signed with **Sigstore Cosign** — signature verified at admission control
- **SBOM** (Software Bill of Materials) generated per build (SPDX format)
- Dependency vulnerability scanning: **OWASP Dependency-Check + Trivy** in CI — build fails on CRITICAL/HIGH CVEs
- **Reproducible builds**: deterministic build hashes; `lock` files committed
- No untrusted registries — all images pulled from internal mirror only

### V.3 Network Security
- **Service mesh (Istio/Linkerd)**: mTLS between all pods — plaintext inter-pod traffic impossible
- **NetworkPolicy**: default-deny-all, explicit ingress/egress rules per service
- **CORS**: strict origin allowlist — `*` is a build-breaking violation
- **API Gateway** as the sole ingress — direct pod exposure impossible
- No cloud metadata endpoint access from application pods

### V.4 Secrets in Infrastructure
- Kubernetes Secrets **not used for sensitive data** — replaced with **External Secrets Operator** pulling from vault
- All Secrets encrypted at rest in etcd (KMS provider)
- **Sealed Secrets** or **SOPS** for secrets in Git (dev/staging only)

---

## Part VI — Observability, Incident Detection & Response

### VI.1 Metrics & Tracing
- **OpenTelemetry SDK** in .NET — traces, metrics, logs exported to OTel Collector
- Trace sampling: **100%** for auth flows; adaptive for others
- **Distributed trace IDs** propagated end-to-end: `traceparent` header mandatory
- Keycloak + .NET API traces correlated by shared `traceId`

### VI.2 Security Monitoring
- **SIEM alerting rules** (mandatory, auto-triggered):
  - ≥ 5 failed logins in 60 seconds from same IP → **block + alert**
  - Token issued with `acr < required_acr` for protected resource → **block + alert**
  - Admin action outside approved maintenance window → **alert**
  - `jti` reuse detected → **block + security incident**
  - TLS downgrade attempt → **block + alert**
  - Certificate validation failure → **block + alert**
  - Config change in Keycloak outside IaC pipeline → **alert**

### VI.3 Audit Trail
- Immutable audit log: **write-once, append-only** (WORM storage or Kafka → cold storage pipeline)
- Every audit entry includes: `timestamp (ISO8601/UTC)`, `actor`, `action`, `resource`, `outcome`, `correlationId`, `ipAddress (hashed)`, `userAgent (hashed)`
- Retention: **7 years** (FedRAMP) / **as required by GDPR data retention policy**
- Audit log integrity verified daily via hash-chain verification job

---

## Part VII — Data Protection & Privacy (GDPR)

### VII.1 Data Classification

| Class | Examples | Controls |
|---|---|---|
| Confidential | PII, auth credentials, health data | Encrypted in transit + at rest; access-logged; DLP |
| Internal | Audit logs, config | Encrypted at rest; role-restricted |
| Public | API docs, metadata | No special controls |

### VII.2 Data Minimization
- Tokens contain only claims strictly required by the resource server — no speculative claims
- User profile data collected: **only what is legally required** for the service
- PII automatically purged after retention period (automated data lifecycle jobs)

### VII.3 Consent & Rights
- Consent tracked in Keycloak user attributes + external consent store (immutable log)
- **Right to Erasure**: automated pseudonymization/anonymization pipeline; auth records de-linked (not deleted — compliance requirement)
- **Data Portability**: export endpoint produces GDPR-compliant JSON export of user data
- **Data Residency**: Keycloak and storage deployed in compliant geographic region; cross-region replication gated by DPA

---

## Part VIII — Development Lifecycle & Quality Gates

### VIII.1 Mandatory Pre-Coding
- **Threat Model** (STRIDE + DREAD) created and approved before any feature branch is opened
- Threat model stored in repo alongside feature code — reviewed in every PR

### VIII.2 CI/CD Quality Gates (ALL must pass; any failure = build blocked)

```
GATE 1 — Static Analysis:   SAST (Semgrep / SonarQube) — zero HIGH/CRITICAL findings
GATE 2 — Dependency Scan:   OWASP Dependency-Check + Trivy — zero CRITICAL CVEs
GATE 3 — Secrets Scan:      Gitleaks / Trufflehog — zero secrets in code/commits
GATE 4 — Test Coverage:     ≥ 90% on security-critical paths; ≥ 80% overall
GATE 5 — DAST:              OWASP ZAP / Nuclei against staging — zero HIGH findings
GATE 6 — IaC Scan:          Checkov / tfsec on all Terraform/Helm — zero HIGH findings
GATE 7 — Container Scan:    Trivy on final image — zero HIGH/CRITICAL CVEs
GATE 8 — SBOM Generation:   SBOM produced, signed, published to artifact registry
GATE 9 — Signature Check:   Base image and dependency signatures verified
```

### VIII.3 Code Review Requirements
- Minimum **2 approvals**: one domain reviewer + one **security-aware reviewer**
- Security reviewers maintain OWASP/security certification (OSCP, CEH, CISSP, or equivalent)
- PRs automatically labelled with security impact scope — high-impact PRs require security team review

### VIII.4 Pre-Release
- **Penetration test** (white-box) by independent team before every major version release
- Penetration test scope: OWASP API Top 10 + FAPI 2.0 compliance + auth flows
- **Red team exercise** annually for production systems

---

## Part IX — API Design Standards

### IX.1 Versioning
- **Semantic Versioning** (MAJOR.MINOR.PATCH) — public contract
- Breaking changes → new **major version** (`/v2/`, `/v3/`)
- **Minimum 6-month deprecation** notice before removing any endpoint or field
- Deprecated endpoints return `Deprecation` and `Sunset` headers (RFC 8594)

### IX.2 API Inventory
- Every endpoint documented in **OpenAPI 3.1** — autogenerated from code annotations
- **No shadow endpoints** — undocumented routes are a build-breaking violation (detected by route-audit CI step)
- API inventory published to internal developer portal

### IX.3 Error Handling
- All errors: **RFC 7807 `ProblemDetails`** format
- Error response contains: `type` (stable URI), `title`, `status`, `correlationId`
- Error response **never** contains: stack traces, internal service names, DB query details, file paths, Keycloak error details

---

## Part X — Governance

### X.1 Authority
This Constitution **supersedes all** other internal guidelines, architectural records, or prior practices in matters of security. In cases of conflict, this document governs.

### X.2 Exception Process
Any deviation from this Constitution requires:
1. **Written justification** with threat analysis
2. **Approval** from the Security Working Group (≥ 3 members, majority vote)
3. **Time-box**: maximum 90 days; renewable with re-approval
4. **Compensating controls** documented and implemented before exception takes effect
5. **Exception record** stored in immutable audit log with expiry alert

### X.3 Amendment Process
1. Pull Request against this document
2. Security Working Group review (minimum 5 business days open for comment)
3. Threat model impact analysis for any relaxation of controls
4. Migration plan for affected systems
5. Version bump + changelog entry
6. Ratification signed by CISO or delegate

### X.4 Compliance Verification
- Automated compliance checks run weekly against live configuration
- Quarterly internal audit against this Constitution
- Annual third-party audit (FedRAMP requirement)
- Non-compliant systems automatically flagged; escalation path: Team Lead → Security Working Group → CISO

---

## Appendix A — Keycloak Feature Activation Checklist

Use this checklist at realm provisioning time. All items marked **[M]** are mandatory.

```
AUTHENTICATION
[M] PKCE S256 enforced via Client Policy
[M] PAR required realm-wide
[M] DPoP enforced on all public clients
[M] MFA mandatory (WebAuthn primary + TOTP secondary)
[M] Passkeys / FIDO2 configured with attestation verification
[M] Step-up authentication flows configured
[M] CIBA configured (push mode only)
[ ] Social Login (only in approved citizen-portal realms)
[M] Kerberos/SPNEGO bridge (AD-joined environments)
[M] SAML 2.0 IdP mode (for legacy integrations)

AUTHORIZATION
[M] RBAC with least-privilege roles
[M] Fine-Grained Authorization Services (UMA 2.0) per API resource server
[M] Fine-Grained Admin Permissions v2
[M] Dynamic Scopes with policy enforcement

TOKEN SECURITY
[M] PS256 signing (RS256 blocked by Client Policy)
[M] JWT token format
[M] Token replay detection (jti cache)
[M] Refresh token rotation
[M] Audience (aud) strict validation
[M] ACR claim validation
[M] Client Secret Rotation policy (≤90 days)

SESSION
[M] Persistent sessions (encrypted in Infinispan cluster)
[M] Global logout (front + back channel)
[M] Concurrent session limits
[M] Short session timeouts (see §II.6)

FEDERATION
[M] LDAPS user federation
[M] Kerberos bridge
[ ] Identity Brokering (with assurance gating)
[ ] Organizations (multi-tenant deployments only)

OPERATIONS
[M] FIPS mode
[M] OpenTelemetry (traces + metrics + logs)
[M] User Event Metrics
[M] Logging MDC
[M] Hostname v2 strict configuration
[M] Clustered Infinispan (production)
[ ] Kubernetes Service Account integration (K8s deployments)
[ ] OID4VC / Verifiable Credentials (digital ID programs)

DISABLED
[✗] JavaScript providers in production
[✗] Dynamic Client Registration in production
[✗] Implicit grant
[✗] ROPC grant
[✗] SMS/email OTP for government employee auth
[✗] Admin impersonation (except dual-approved, time-boxed)
[✗] RS256 / HS256 signing
[✗] Clusterless mode in production
```

---

## Appendix B — Quick Reference: Prohibited Patterns

| Pattern | Reason | Correct Alternative |
|---|---|---|
| `RS256` or `HS256` tokens | Weak; HS256 key confusion attacks | PS256 or ES256 |
| ROPC grant | Password exposed to client | Auth Code + PKCE |
| Implicit flow | Token in URL fragment | Auth Code + PKCE |
| Long-lived access tokens (> 15 min) | Replay window | Short-lived + DPoP |
| Static client secrets (no rotation) | Credential stuffing | mTLS + secret rotation |
| PII in JWT claims | Data exposure | Opaque user ID (`sub`) only |
| Stack traces in API errors | Information leakage | RFC 7807 ProblemDetails |
| `*` in CORS `Allow-Origin` | Cross-site token theft | Explicit origin allowlist |
| Secrets in `appsettings.json` | Source code exposure | Vault provider |
| TLS < 1.3 | Known vulnerabilities | TLS 1.3 only |
| `ValidateLifetime = false` | Token replay | Never disable |
| `ClockSkew > 0` | Token replay window | `ClockSkew = Zero` |
| `[AllowAnonymous]` on sensitive routes | Auth bypass | Explicit policy required |

---

**Version**: 2.0.0  
**Ratified**: 2026-03-13  
**Status**: Active — supersedes v1.0.0  
**Owners**: Security Working Group  
**Review Cycle**: Quarterly + on any major Keycloak or .NET release