# Specification: [Feature / Component Name]

> **Template Version**: 1.0.0 | **Constitution Ref**: FortressAPI Constitution v2.0.0  
> **Status**: `DRAFT` | `UNDER REVIEW` | `APPROVED` | `SUPERSEDED`  
> Copy this file to `specify/specs/[YYYY-MM-DD]-[slug].md` and fill every section.  
> Sections marked **[MANDATORY]** cannot be left empty — the PR will be blocked.

---

## Meta

| Field | Value |
|---|---|
| **Spec ID** | SPEC-XXXX |
| **Title** | |
| **Author(s)** | |
| **Security Reviewer** | *(must hold OSCP / CEH / CISSP or equivalent)* |
| **Created** | YYYY-MM-DD |
| **Last Updated** | YYYY-MM-DD |
| **Target Version** | MAJOR.MINOR |
| **Linked Plan** | PLAN-XXXX |
| **Linked Tasks** | TASK-XXXX, TASK-XXXX |
| **Supersedes** | *(SPEC-XXXX or N/A)* |
| **Compliance Scope** | NIST 800-63-3 / FedRAMP / GDPR / FAPI 2.0 / OWASP API 2023 *(delete inapplicable)* |

---

## 1. Overview **[MANDATORY]**

### 1.1 Problem Statement
<!--
What problem does this feature solve?
Who is affected and what is the current state?
Be precise — no marketing language.
-->

### 1.2 Proposed Solution Summary
<!--
One paragraph. What is being built, at what layer, and for whom?
Reference any prior RFCs, ADRs, or spike results.
-->

### 1.3 Out of Scope
<!--
Explicitly list what this spec does NOT cover.
This prevents scope creep and unreviewed surface expansion.
-->

---

## 2. Stakeholders & Actors **[MANDATORY]**

| Role | Name / Team | Responsibility |
|---|---|---|
| Feature Owner | | Final acceptance |
| Security Reviewer | | Threat model sign-off |
| IAM Architect | | Keycloak/OIDC design approval |
| Data Protection Officer | | GDPR impact sign-off *(if PII involved)* |
| Operations | | Deployment, observability sign-off |

### 2.1 User / System Actors

| Actor | Type | Trust Level | Auth Mechanism |
|---|---|---|---|
| *(e.g. Government Employee)* | Human | AAL2 | WebAuthn + TOTP |
| *(e.g. Partner Agency Service)* | System | Confidential Client | mTLS + Client Credentials |
| *(e.g. Mobile App)* | Public Client | AAL2 | Auth Code + PKCE + DPoP |

---

## 3. Functional Requirements **[MANDATORY]**

> Use `SHALL` for mandatory, `SHOULD` for recommended, `MAY` for optional (RFC 2119).

### 3.1 Core Requirements

| ID | Requirement | Priority |
|---|---|---|
| FR-01 | The system SHALL … | P0 — Blocker |
| FR-02 | The system SHALL … | P1 — High |
| FR-03 | The system SHOULD … | P2 — Medium |

### 3.2 API Contract

#### Endpoints

```
METHOD  /v{N}/[resource-path]
```

| Field | Detail |
|---|---|
| **HTTP Method** | |
| **Path** | `/v1/` |
| **Auth Required** | Yes — Bearer (PS256 JWT) + DPoP |
| **Required Scope** | `resource:action` |
| **Required ACR** | `acr1` / `acr2` / `acr3` |
| **Required Role** | |
| **Rate Limit** | X req/min per `sub` |
| **Idempotency** | Yes / No — `Idempotency-Key` header |

##### Request Body Schema

```jsonc
{
  // Define schema here — every field with type, constraints, and whether required
  // No $ref to external schemas without explicit version pinning
}
```

##### Response Body Schema

```jsonc
{
  // Only fields that are explicitly authorized to be returned
  // No speculative fields — see Constitution §III.2 property-level authorization
}
```

##### Error Responses (RFC 7807 ProblemDetails)

| HTTP Status | `type` URI | Condition |
|---|---|---|
| 400 | `/errors/validation` | Invalid input |
| 401 | `/errors/unauthorized` | Missing or invalid token |
| 403 | `/errors/forbidden` | Insufficient scope or ACR |
| 404 | `/errors/not-found` | Resource does not exist |
| 409 | `/errors/conflict` | State conflict |
| 422 | `/errors/unprocessable` | Semantic validation failure |
| 429 | `/errors/rate-limited` | Rate limit exceeded |
| 500 | `/errors/internal` | Internal error — no detail exposed |

### 3.3 Data Model

```
Entity: [Name]
Fields:
  - id          : UUID v7          [PK, immutable]
  - [field]     : [type]           [constraints]
  - created_at  : ISO8601 UTC      [immutable, system-set]
  - updated_at  : ISO8601 UTC      [system-set]
  - deleted_at  : ISO8601 UTC|null [soft-delete only]

Classification: CONFIDENTIAL / INTERNAL / PUBLIC
PII Fields: [list or "none"]
Retention: [period + legal basis]
```

---

## 4. Non-Functional Requirements **[MANDATORY]**

### 4.1 Security Requirements

| Requirement | Specification | Constitution Ref |
|---|---|---|
| Authentication | *(e.g. Auth Code + PKCE S256 + PAR + DPoP)* | §II.1, §II.4 |
| Authorization | *(e.g. UMA 2.0 resource policy + scope check)* | §II.5 |
| Token Signing | PS256 / ES256 only | §IV.1 |
| Token Lifetime | Access ≤ 5 min, Refresh ≤ 8 h + rotation | §II.4 |
| MFA Requirement | *(e.g. WebAuthn mandatory)* | §II.3 |
| Step-Up Auth | *(e.g. required for scope `finance:write`)* | §II.3 |
| Transport | TLS 1.3 only, HSTS preload | §III.4 |
| BOLA Prevention | *(mechanism)* | §II.5, §III.2 |
| Input Validation | FluentValidation schema | §III.3 |
| Output Encoding | JSON only, explicit DTO allow-list | §III.3 |
| Rate Limiting | *(req/min per sub + per IP)* | §III.6 |
| Audit Logging | All state changes logged to SIEM | §VI.3 |
| Data Classification | *(CONFIDENTIAL / INTERNAL / PUBLIC)* | §VII.1 |
| FIPS Compliance | FIPS 140-3 algorithms only | §IV.3 |

### 4.2 Performance Requirements

| Metric | Target | Measurement Method |
|---|---|---|
| p99 latency | ≤ X ms | Distributed trace — OTel |
| Throughput | X req/s sustained | Load test — k6 |
| Error rate | < 0.1% under target load | |
| Availability | 99.9% / 99.99% | SLO dashboard |

### 4.3 Observability Requirements

- [ ] Distributed trace spans emitted for all I/O operations
- [ ] Metrics: `[counter/histogram name]` exported via OTel
- [ ] Structured log fields: `correlationId`, `sub`, `clientId`, `action`, `outcome`
- [ ] Alert rule: *(define alert condition and severity)*
- [ ] SIEM event: *(define security event type and payload)*

---

## 5. Threat Model **[MANDATORY — PR BLOCKED WITHOUT THIS]**

> Method: **STRIDE + DREAD**. Every identified threat must have a documented mitigation before the spec is approved.

### 5.1 Assets & Trust Boundaries

```
Assets:
  - [Asset 1]: [sensitivity level]
  - [Asset 2]: [sensitivity level]

Trust Boundaries Crossed:
  - Internet → API Gateway
  - API Gateway → .NET Web API
  - .NET Web API → Keycloak
  - .NET Web API → Database
```

### 5.2 STRIDE Analysis

| ID | Threat | STRIDE Category | Component | DREAD Score | Mitigation | Status |
|---|---|---|---|---|---|---|
| T-01 | *(e.g. Attacker replays captured access token)* | Repudiation / Spoofing | Token validation | 8/10 | `jti` replay cache + DPoP binding | ✅ Mitigated |
| T-02 | | | | | | ⚠️ Accepted |
| T-03 | | | | | | 🔴 Open |

**DREAD Scoring** (1–10 each, average = total):  
`D`amage · `R`eproducibility · `E`xploitability · `A`ffected users · `D`iscoverability

### 5.3 OWASP API Top 10 (2023) Coverage

| Risk | Applicable? | Mitigation |
|---|---|---|
| API1 — Broken Object Level Authorization | Yes / No | |
| API2 — Broken Authentication | Yes / No | |
| API3 — Broken Object Property Level Auth | Yes / No | |
| API4 — Unrestricted Resource Consumption | Yes / No | |
| API5 — Broken Function Level Authorization | Yes / No | |
| API6 — Unrestricted Access to Sensitive Flows | Yes / No | |
| API7 — Server-Side Request Forgery | Yes / No | |
| API8 — Security Misconfiguration | Yes / No | |
| API9 — Improper Inventory Management | Yes / No | |
| API10 — Unsafe Consumption of APIs | Yes / No | |

### 5.4 Residual Risks

| Risk | Likelihood | Impact | Accepted By | Review Date |
|---|---|---|---|---|
| | | | | |

---

## 6. Keycloak Configuration **[MANDATORY if auth-related]**

### 6.1 Client Configuration

```json
{
  "clientId": "",
  "clientType": "public | confidential | bearer-only",
  "protocol": "openid-connect",
  "redirectUris": [],
  "webOrigins": [],
  "attributes": {
    "pkce.code.challenge.method": "S256",
    "dpop.bound.access.tokens": "true",
    "require.pushed.authorization.requests": "true",
    "token.endpoint.auth.signing.alg": "PS256",
    "access.token.lifespan": "300",
    "use.refresh.tokens": "true",
    "refresh.token.max.reuse": "0"
  }
}
```

### 6.2 Scopes Required

| Scope | Purpose | Granted To |
|---|---|---|
| | | |

### 6.3 Resource & Policy (UMA 2.0)

```
Resource Name   : 
Resource URI    : /v1/[resource]/*
Scopes          : read, write, delete
Policy Type     : Resource-based / Attribute-based / Time-based
Policy Logic    : ALL / ANY / UNANIMOUS
Assigned Roles  : 
```

### 6.4 Authentication Flow

```
Flow Name       : 
Steps           :
  1. 
  2. 
  3. 
Step-Up Trigger : *(scope / ACR / resource)*
Required ACR    : 
```

### 6.5 Client Policy Compliance

- [ ] `pkce-enforcer` — S256 enforced
- [ ] `dpop-enforcer` — enabled for public clients
- [ ] `par-enforcer` — PAR required
- [ ] `secure-signing-algorithm` — PS256/ES256 only
- [ ] `holder-of-key-enforcer` — mTLS or DPoP binding

---

## 7. .NET Implementation Notes

### 7.1 Authorization Policy

```csharp
// Describe the policy to register in Program.cs
// builder.Services.AddAuthorization(options =>
// {
//     options.AddPolicy("PolicyName", policy =>
//         policy.RequireClaim("scope", "required:scope")
//               .RequireClaim("acr", "acr2"));
// });
```

### 7.2 Endpoint Security Annotation

```csharp
[Authorize(Policy = "PolicyName")]
[RequireHttps]
// HttpMethod, route, rate-limit attribute
```

### 7.3 Input Validation Contract

```csharp
// Define FluentValidation rules
// Every field: NotEmpty/NotNull + type constraint + range/length + format (regex if needed)
// RuleFor(x => x.Field).NotEmpty().MaximumLength(N).Matches(@"regex");
```

### 7.4 Response DTO (Explicit Allow-List)

```csharp
// Define the response DTO
// ONLY include properties that are authorized to be returned
// No entity objects passed directly — explicit mapper required
public sealed record [Name]Response(
    // properties
);
```

---

## 8. Data Protection & Privacy **[MANDATORY if PII involved]**

### 8.1 GDPR / Data Protection Impact

| Question | Answer |
|---|---|
| Does this feature process PII? | Yes / No |
| Legal basis for processing | Consent / Legal Obligation / Legitimate Interest |
| Data subject categories | *(e.g. Government employees, Citizens)* |
| PII fields processed | *(list or "none")* |
| Data minimization measure | *(what is not collected and why)* |
| Retention period | |
| Cross-border transfer? | Yes / No — if Yes, adequacy decision or SCC in place? |
| DPIA required? | Yes / No — if Yes, attach reference |

### 8.2 Data Flows

```
[Data Source] → [This Component] → [Downstream]
Sensitivity at each hop: [CONFIDENTIAL / INTERNAL]
Encryption in transit: TLS 1.3 mTLS
Encryption at rest: AES-256-GCM
```

---

## 9. Dependencies & Integration Points

| Dependency | Type | Version Pinned | Security Notes |
|---|---|---|---|
| Keycloak | IAM / IdP | 26.x | FIPS mode enabled |
| *(Library)* | NuGet | X.Y.Z | CVE scan: clean |
| *(External API)* | HTTP | | mTLS + timeout + circuit breaker |

---

## 10. Rollout & Operational Concerns

### 10.1 Feature Flags

| Flag | Default | Purpose | Removal Condition |
|---|---|---|---|
| `feature.[name]` | `false` | Gradual rollout | After N% traffic validation |

### 10.2 Migration & Compatibility

- Breaking change? **Yes / No**
- If yes: new API version required (`/v{N+1}/`)
- Deprecation notice period: minimum 6 months
- `Deprecation` + `Sunset` headers added to old version: **Yes / No**

### 10.3 Rollback Plan

<!--
Describe how to revert this feature in production without data loss.
Keycloak config changes: which Client Policies / flows to revert.
Database changes: are migrations reversible?
-->

---

## 11. Acceptance Criteria **[MANDATORY]**

All criteria must be met before the feature is considered complete.

### 11.1 Functional

- [ ] FR-01: *(test scenario)*
- [ ] FR-02: *(test scenario)*

### 11.2 Security

- [ ] Threat model reviewed and all T-XX threats mitigated or formally accepted
- [ ] OWASP API Top 10 coverage verified for applicable risks
- [ ] FAPI 2.0 compliance validated (PAR + PKCE + DPoP + PS256)
- [ ] Token replay protection verified (`jti` cache tested)
- [ ] BOLA test: user A cannot access user B's resources
- [ ] ACR enforcement verified: step-up triggered correctly
- [ ] Rate limiting tested: threshold triggers 429 + alert
- [ ] No PII in logs verified (log audit)
- [ ] No stack traces in error responses verified
- [ ] All CORS origins restricted (no `*`)
- [ ] SAST gate passed: zero HIGH/CRITICAL findings
- [ ] Dependency scan passed: zero CRITICAL CVEs

### 11.3 Non-Functional

- [ ] p99 latency ≤ target under load test
- [ ] OTel traces visible end-to-end in tracing backend
- [ ] Audit log entries verified in SIEM for all state-changing operations
- [ ] Security alert fires correctly in SIEM for simulated attack scenario

---

## 12. Open Questions

| # | Question | Owner | Due | Resolution |
|---|---|---|---|---|
| 1 | | | | |

---

## 13. References

- [FortressAPI Constitution v2.0.0](../constitution.md)
- [NIST SP 800-63-3](https://pages.nist.gov/800-63-3/)
- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-2_0-security-profile.html)
- [RFC 9449 — DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 9126 — PAR](https://datatracker.ietf.org/doc/html/rfc9126)
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/)
- *(Add relevant ADRs, RFCs, internal documents)*

---

## Approval Sign-Off **[MANDATORY]**

| Role | Name | Signature / Approval Link | Date |
|---|---|---|---|
| Feature Owner | | | |
| Security Reviewer | | | |
| IAM Architect | | | |
| DPO *(if PII)* | | | |

> **Spec is not approved until all mandatory sign-offs are recorded.**  
> Approval is recorded as a PR approval + comment with `APPROVED: SPEC-XXXX` on the spec file.