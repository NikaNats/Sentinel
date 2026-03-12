# Implementation Plan: [Feature / Component Name]

> **Template Version**: 1.0.0 | **Constitution Ref**: FortressAPI Constitution v2.0.0  
> **Status**: `DRAFT` | `APPROVED` | `IN PROGRESS` | `COMPLETED` | `ABANDONED`  
> Copy this file to `specify/plans/[YYYY-MM-DD]-[slug].md` before filling.  
> A plan must be linked to an **APPROVED** spec. An unapproved spec blocks this plan.

---

## Meta

| Field | Value |
|---|---|
| **Plan ID** | PLAN-XXXX |
| **Title** | |
| **Linked Spec** | SPEC-XXXX *(must be APPROVED)* |
| **Linked Tasks** | TASK-XXXX *(generated from this plan)* |
| **Author(s)** | |
| **Tech Lead** | |
| **Security Reviewer** | |
| **Created** | YYYY-MM-DD |
| **Last Updated** | YYYY-MM-DD |
| **Target Branch** | `feature/SPEC-XXXX-[slug]` |
| **Target Release** | vMAJOR.MINOR |
| **Estimated Effort** | X dev-days |

---

## 1. Pre-Implementation Checklist **[ALL must be ✅ before any code is written]**

| Gate | Requirement | Status |
|---|---|---|
| Spec | SPEC-XXXX is in `APPROVED` state | ☐ |
| Threat Model | STRIDE/DREAD complete, all HIGH threats mitigated | ☐ |
| Security Sign-Off | Security reviewer has approved the spec | ☐ |
| DPO Sign-Off | DPO approved (if PII is involved) | ☐ |
| Branch Policy | Feature branch created from `main`; branch protection rules active | ☐ |
| FIPS Check | Target crypto algorithms verified as FIPS 140-3 compliant | ☐ |
| Keycloak Config | Client + Resource + Policy design reviewed by IAM Architect | ☐ |
| API Contract | OpenAPI 3.1 draft exists and has been reviewed | ☐ |
| Dependency Audit | New NuGet dependencies scanned — zero CRITICAL CVEs | ☐ |
| Feature Flag | Feature flag key defined; default = `false` in all environments | ☐ |

---

## 2. Architecture Overview

### 2.1 Component Diagram

```
[Client / Browser]
      │  Auth Code + PKCE + PAR + DPoP
      ▼
[Keycloak 26+]  ──────────────────────────────────────────
      │  PS256 JWT (DPoP-bound)                           │
      ▼                                              [LDAP/AD]
[API Gateway]                                        [SIEM]
      │  mTLS + JWT forward
      ▼
[.NET Web API]
      │  UMA 2.0 introspection / token validation
      ├─► [Keycloak Authorization Services]
      │
      ├─► [Database (EF Core — parameterized queries)]
      │
      ├─► [Cache (Redis — jti replay store)]
      │
      └─► [OTel Collector → Tracing / Metrics / Logs]
```

> Update this diagram to reflect the actual topology for this feature.

### 2.2 Data Flow Narrative

<!--
Walk through the primary happy path in prose:
1. Who initiates the request and how?
2. How does the token get issued (Keycloak flow)?
3. How does the .NET API validate and authorize?
4. What data is read/written and where?
5. What is returned to the caller?
Keep it precise — this is not marketing copy.
-->

### 2.3 New vs Modified Components

| Component | Change Type | Description |
|---|---|---|
| `[ProjectName].Api` | New / Modified | |
| `[ProjectName].Domain` | New / Modified | |
| `[ProjectName].Infrastructure` | New / Modified | |
| Keycloak Realm Config | New Client / Policy / Flow | |
| OTel Config | New metrics / spans | |
| CI Pipeline | New gate | |

---

## 3. Keycloak Implementation Plan

### 3.1 Realm / Client Changes

```
Realm       : [realm-name]
Client ID   : [client-id]
Change Type : CREATE / UPDATE

Changes:
  - [ ] Register client with required attributes (see Spec §6.1)
  - [ ] Apply Client Policy profile: [profile-name]
  - [ ] Verify pkce-enforcer: S256
  - [ ] Verify dpop-enforcer: enabled
  - [ ] Verify par-enforcer: enabled
  - [ ] Verify signing alg: PS256
  - [ ] Set access_token_lifespan: 300s (or per spec)
  - [ ] Set refresh_token_max_reuse: 0 (rotation enabled)
  - [ ] Configure back-channel logout URI
  - [ ] Configure front-channel logout URI
```

### 3.2 Resource Server & Authorization Policy

```
Resource Server : [client-id]-resource-server

Resources to register:
  ┌─────────────────────────────────────────────────────────────┐
  │ Resource Name │ URI Pattern       │ Scopes              │ Policy │
  ├───────────────┼───────────────────┼─────────────────────┼────────┤
  │               │ /v1/[resource]/*  │ read / write        │        │
  └─────────────────────────────────────────────────────────────┘

Policies:
  - [ ] Role-based policy: [role] → [scope]
  - [ ] Attribute-based policy: [attribute condition]
  - [ ] Time-based policy: [if applicable]
  - [ ] Permission: UNANIMOUS strategy (all policies must allow)
```

### 3.3 Authentication Flow

```
Flow: [flow-name]
Type: Browser / Direct Grant / Client Credentials / CIBA

Steps:
  1. Username / Email identification
  2. Password (if applicable)
  3. WebAuthn / Passkey challenge
  4. [Step-up trigger: scope X requires re-auth]
  5. PAR request object validated
  6. PKCE S256 challenge verified
  7. DPoP proof verified at token endpoint

Required ACR mapping:
  acr1 → password only             [not permitted for gov users]
  acr2 → password + TOTP
  acr3 → WebAuthn / passkey (preferred)
```

### 3.4 Configuration as Code

- [ ] Keycloak realm config exported as **JSON / Terraform** and committed to repo
- [ ] Config changes reviewed as part of the PR — no manual console-only changes in staging/production
- [ ] Config applied via CI pipeline (not manually) in staging and production
- [ ] Config diff reviewed by IAM Architect before merge

---

## 4. .NET Web API Implementation Plan

### 4.1 Project Structure

```
src/
├── [ProjectName].Api/
│   ├── Controllers/
│   │   └── [Resource]Controller.cs       ← endpoint definition
│   ├── Middleware/
│   │   ├── DpopValidationMiddleware.cs    ← DPoP proof verification
│   │   ├── TokenReplayMiddleware.cs       ← jti cache check
│   │   └── AcrValidationMiddleware.cs     ← ACR enforcement
│   ├── Authorization/
│   │   ├── [Resource]AuthorizationHandler.cs
│   │   └── Policies/
│   └── Program.cs
├── [ProjectName].Application/
│   ├── [Feature]/
│   │   ├── Commands/
│   │   ├── Queries/
│   │   └── Validators/                   ← FluentValidation rules
├── [ProjectName].Domain/
│   └── [Aggregate]/
└── [ProjectName].Infrastructure/
    ├── Persistence/                       ← EF Core (parameterized only)
    ├── Cache/                             ← Redis (jti replay store)
    └── Keycloak/                          ← introspection / UMA client
```

### 4.2 Authentication & Authorization Setup

```csharp
// Step-by-step setup in Program.cs

// 1. JWT Bearer — Keycloak issuer, PS256, strict validation
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => {
        options.Authority = "https://[keycloak-host]/realms/[realm]";
        options.Audience  = "[client-id]";
        options.TokenValidationParameters = new() {
            ValidateIssuer           = true,
            ValidateAudience         = true,
            ValidateLifetime         = true,
            ClockSkew                = TimeSpan.Zero,    // NO tolerance
            ValidAlgorithms          = ["PS256", "ES256"],
            RequireSignedTokens      = true,
            RequireExpirationTime    = true,
        };
        options.RequireHttpsMetadata = true;
    });

// 2. Authorization policies (from Spec §6.2 / §6.3)
builder.Services.AddAuthorization(options => {
    options.AddPolicy("[PolicyName]", policy =>
        policy.RequireClaim("scope", "[required:scope]")
              .Requirements.Add(new AcrRequirement("[acr2]")));
});

// 3. DPoP validation middleware (before auth middleware)
app.UseMiddleware<DpopValidationMiddleware>();

// 4. Token replay middleware (jti cache)
app.UseMiddleware<TokenReplayMiddleware>();

// 5. Standard pipeline order
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
```

### 4.3 Security Middleware Implementation Notes

#### DPoP Validation
- Validate `DPoP` header presence on all non-public endpoints
- Verify proof JWT signature using public key from `Authorization` token's `cnf.jkt`
- Verify `htm` (HTTP method) and `htu` (HTTP URL) match request
- Verify `iat` freshness (≤ 60 seconds)
- Verify server-issued nonce (if nonce challenge active)
- Reject with `401 + WWW-Authenticate: DPoP error="invalid_dpop_proof"` on failure

#### Token Replay (`jti` cache)
- On every authenticated request: extract `jti` from validated token
- Check Redis key `jti:{value}` — if exists → **reject 401**, log security event
- If absent → SET with TTL = token `exp - now` (atomic operation)
- Redis key prefix: `replay:jti:` — isolated from application cache namespace

#### ACR Enforcement
- Read required ACR from endpoint policy
- Compare against `acr` claim in validated token
- Insufficient ACR → **401 with `WWW-Authenticate: Bearer error="insufficient_user_authentication"`**
- This triggers the client to initiate a step-up flow via Keycloak

### 4.4 Input Validation Strategy

```
Every request object MUST have a corresponding FluentValidation validator.
Validation rules:
  - Required fields: NotEmpty() / NotNull()
  - Strings: MaximumLength(N) + Matches(@"safe-regex")
  - IDs: Must be valid UUID — no freeform strings as IDs
  - Enums: IsInEnum() — never accept raw integer without enum mapping
  - Numbers: InclusiveBetween(min, max)
  - Dates: Must be UTC, must be within sane range
  - Collections: Must(c => c.Count <= N) — prevent unbounded inputs

Validation failure → 400 ProblemDetails (no field-level detail that aids enumeration)
```

### 4.5 Output / Response Strategy

```
Response DTOs:
  - Defined as sealed records — immutable
  - Named [Resource]Response — never expose domain entity directly
  - Only properties explicitly authorized are included (property-level auth)
  - No computed navigation properties that could expose related data
  - Nullable fields return null — never omitted (prevents information leakage via field presence)

Mapping:
  - Manual mapping or Mapperly (compile-time, no reflection) — never AutoMapper with reflection
  - Mapping tests cover all properties of the DTO — new fields fail the test until explicitly mapped
```

---

## 5. Database & Persistence Plan

### 5.1 Schema Changes

```sql
-- Migration name: [YYYYMMDDHHMMSS]_[DescriptiveName]
-- Impact: Non-breaking / Breaking (if breaking → new API version required)

-- Tables Added / Modified:
--   [table_name]: [description of change]

-- Indexes:
--   [index on field]: [justification — performance / uniqueness]

-- No raw SQL in application code — EF Core parameterized queries only
```

### 5.2 Data Access Notes

- All queries via EF Core — no `FromSqlRaw` without explicit parameterization review
- Sensitive fields encrypted at the application layer before write (AES-256-GCM)
- Soft-delete only (`deleted_at` timestamp) — hard deletes only via data lifecycle job
- No bulk operations without explicit rate-limiting and audit logging

---

## 6. Observability Plan

### 6.1 Tracing

| Span Name | Parent | Key Attributes | Sampling |
|---|---|---|---|
| `[feature].[operation]` | HTTP request span | `user.id`, `resource.id`, `outcome` | 100% |

### 6.2 Metrics

| Metric Name | Type | Labels | Alert Threshold |
|---|---|---|---|
| `[feature]_requests_total` | Counter | `method`, `status`, `outcome` | |
| `[feature]_duration_seconds` | Histogram | `method` | p99 > Xms → alert |
| `[feature]_auth_failures_total` | Counter | `reason` | > 5/min → SIEM alert |

### 6.3 Structured Log Events

| Event | Level | Required Fields | SIEM? |
|---|---|---|---|
| `[Feature].Accessed` | Information | `sub`, `resourceId`, `scope`, `correlationId` | No |
| `[Feature].Created` | Information | `sub`, `resourceId`, `correlationId` | Yes |
| `[Feature].AuthFailed` | Warning | `sub`, `reason`, `correlationId`, `ip_hash` | Yes |
| `[Feature].PolicyDenied` | Warning | `sub`, `policy`, `resource`, `correlationId` | Yes |

---

## 7. CI/CD Pipeline Changes

### 7.1 New Pipeline Steps Required

- [ ] Route-audit step: verify no undocumented endpoints introduced
- [ ] OpenAPI diff check: detect breaking changes vs previous version
- [ ] New FluentValidation coverage test: all request types have a validator
- [ ] SAST rule additions: *(list new Semgrep rules if any)*
- [ ] Integration test suite: new test collection for this feature

### 7.2 Environment Promotion Gates

```
DEV  →  STAGING  →  PRODUCTION

DEV:
  - Unit tests pass
  - SAST: zero CRITICAL
  - Secrets scan: clean

STAGING:
  - Integration tests pass (including Keycloak flows)
  - DAST: zero HIGH findings
  - Performance baseline met (k6)
  - Feature flag: staged rollout to X% traffic

PRODUCTION:
  - All STAGING gates passed
  - Security reviewer sign-off on diff since last deploy
  - Rollback plan verified (dry-run)
  - On-call rotation notified
```

---

## 8. Security Validation Plan

### 8.1 Security Test Scenarios

| # | Scenario | Expected Outcome | Test Type |
|---|---|---|---|
| S-01 | Request with expired access token | 401 Unauthorized | Integration |
| S-02 | Request with invalid DPoP proof | 401 + `invalid_dpop_proof` | Integration |
| S-03 | Request with replayed `jti` | 401 Unauthorized | Integration |
| S-04 | User A requests User B's resource (BOLA) | 403 Forbidden | Integration |
| S-05 | Request with ACR below required level | 401 + step-up hint | Integration |
| S-06 | Mass assignment — extra fields in request body | Fields silently ignored | Integration |
| S-07 | Rate limit threshold exceeded | 429 + Retry-After | Integration |
| S-08 | SQL injection in query param | 400 / no error detail | Integration |
| S-09 | Token with `RS256` algorithm | 401 (algorithm rejected) | Integration |
| S-10 | Missing `aud` claim | 401 Unauthorized | Integration |
| S-11 | Scope missing from token | 403 Forbidden | Integration |
| S-12 | No HTTPS (HTTP request) | Redirect / Reject | Integration |

### 8.2 Manual Security Review Checklist (pre-merge)

- [ ] All endpoints have `[Authorize(Policy = "...")]` — no implicit access
- [ ] No `[AllowAnonymous]` without documented justification in threat model
- [ ] All SQL access goes through EF Core parameterized path
- [ ] All external HTTP calls have timeout + retry + circuit breaker
- [ ] No secrets hardcoded or logged
- [ ] DPoP validation cannot be bypassed (middleware order verified)
- [ ] Error responses contain only `ProblemDetails` — no internal detail

---

## 9. Rollout Strategy

### 9.1 Phase Plan

| Phase | Scope | Duration | Rollback Trigger |
|---|---|---|---|
| 0 — Dark Launch | Internal team only, feature flag off | 3 days | Any P0 bug |
| 1 — Canary | 5% of traffic, feature flag on | 3 days | Error rate > 0.5% |
| 2 — Staged | 25% → 50% → 100% | 7 days | Error rate > 0.1% |
| 3 — GA | Feature flag removed | After N days stable | |

### 9.2 Rollback Procedure

```
1. Disable feature flag → traffic falls back immediately (< 30s)
2. If config change required: revert Keycloak config via IaC pipeline
3. If DB migration required: run down migration (verify tested in staging)
4. Notify on-call + security team of rollback event
5. File incident report within 24 hours
```

---

## 10. Open Questions & Decisions

| # | Question | Decision | Owner | Date |
|---|---|---|---|---|
| 1 | | | | |

### 10.1 Architecture Decision Records (ADRs)

| ADR | Decision | Status |
|---|---|---|
| ADR-XXXX | *(e.g. Use DPoP nonces vs stateless DPoP)* | Accepted |

---

## 11. Definition of Done **[ALL must be ✅ for COMPLETED status]**

### Code
- [ ] All functional requirements from SPEC-XXXX implemented
- [ ] All security requirements from SPEC-XXXX implemented
- [ ] Code reviewed: ≥ 2 approvals (domain + security reviewer)
- [ ] No `TODO` or `FIXME` comments related to security paths

### Tests
- [ ] Unit test coverage ≥ 90% on security-critical paths
- [ ] All S-XX security test scenarios pass
- [ ] Integration tests covering full auth flow (PAR → token → DPoP request)
- [ ] Load test confirms p99 latency target met

### CI/CD
- [ ] All 9 CI gates pass (SAST, dependency scan, secrets scan, DAST, IaC scan, etc.)
- [ ] OpenAPI spec updated and committed
- [ ] Keycloak config committed as code and applied via pipeline

### Observability
- [ ] Traces visible end-to-end in production tracing tool
- [ ] Metrics dashboards updated
- [ ] SIEM alert rules deployed and verified with synthetic event

### Documentation
- [ ] SPEC-XXXX status updated to `COMPLETED`
- [ ] API changelog entry added
- [ ] Any new operational runbooks written
- [ ] Threat model final state archived

---

## References

- [SPEC-XXXX](../specs/SPEC-XXXX.md)
- [FortressAPI Constitution v2.0.0](../../constitution.md)
- [Keycloak 26 Documentation](https://www.keycloak.org/documentation)
- [RFC 9449 — DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 9126 — PAR](https://datatracker.ietf.org/doc/html/rfc9126)
- *(Add ADRs, runbooks, relevant internal links)*