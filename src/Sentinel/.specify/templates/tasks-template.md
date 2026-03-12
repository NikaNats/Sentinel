# Tasks: [Feature / Component Name]

> **Template Version**: 1.0.0 | **Constitution Ref**: FortressAPI Constitution v2.0.0  
> **Status**: `PLANNED` | `IN PROGRESS` | `BLOCKED` | `COMPLETED`  
> Copy to `specify/tasks/[YYYY-MM-DD]-[slug].md`. Tasks are derived from an **APPROVED** plan.  
> Every task that touches auth, tokens, or security paths is a **security task** and requires security reviewer sign-off on its PR.

---

## Meta

| Field | Value |
|---|---|
| **Tasks ID** | TASK-XXXX |
| **Feature** | |
| **Linked Spec** | SPEC-XXXX |
| **Linked Plan** | PLAN-XXXX |
| **Author** | |
| **Tech Lead** | |
| **Sprint / Milestone** | |
| **Created** | YYYY-MM-DD |
| **Last Updated** | YYYY-MM-DD |
| **Total Estimated** | X dev-days |

---

## Progress Summary

```
Total  : XX tasks
Done   : 00 ░░░░░░░░░░░░░░░░░░░░  0%
Active : 00
Blocked: 00
```

---

## Task Legend

| Symbol | Meaning |
|---|---|
| 🔴 | Security task — requires security reviewer on PR |
| 🔒 | Keycloak / IAM task |
| 🧪 | Test / validation task |
| 🔧 | Infrastructure / pipeline task |
| 📄 | Documentation task |
| ⚡ | Blocks other tasks (critical path) |

**Priority**: `P0` Blocker · `P1` High · `P2` Medium · `P3` Low  
**Status**: `TODO` · `IN PROGRESS` · `IN REVIEW` · `DONE` · `BLOCKED`

---

## Phase 0 — Pre-Coding Gates ⚡

> All Phase 0 tasks must be `DONE` before any Phase 1 task begins.

---

### TASK-XXXX-001 · Threat Model Review & Sign-Off 🔴⚡

| Field | Value |
|---|---|
| **Priority** | P0 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 0.5 day |
| **Reviewer** | Security Reviewer (mandatory) |
| **Branch** | N/A — document task |

**What**  
Review the STRIDE/DREAD threat model in SPEC-XXXX §5. Verify every HIGH/CRITICAL threat has a documented mitigation. Sign off in the spec PR.

**Acceptance Criteria**
- [ ] All T-XX threats rated ≥ 7/10 DREAD have a mitigation status of `✅ Mitigated`
- [ ] No threat marked `🔴 Open` — must be mitigated or formally accepted with compensating control
- [ ] Security reviewer approval recorded in SPEC-XXXX PR

**Constitution Ref**: §VIII.1

---

### TASK-XXXX-002 · Keycloak Config Design Review 🔒⚡

| Field | Value |
|---|---|
| **Priority** | P0 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 0.5 day |
| **Reviewer** | IAM Architect (mandatory) |

**What**  
Review the Keycloak client, resource, policy, and flow design from PLAN-XXXX §3. Verify alignment with Client Policies and FAPI 2.0 profile.

**Acceptance Criteria**
- [ ] Client attributes verified: PKCE S256, DPoP, PAR, PS256, token lifetimes
- [ ] UMA 2.0 resource/scope/policy structure approved
- [ ] Authentication flow steps reviewed
- [ ] IAM Architect approval recorded in PLAN-XXXX PR

**Constitution Ref**: §II.1–§II.5

---

### TASK-XXXX-003 · Dependency Audit 🔧⚡

| Field | Value |
|---|---|
| **Priority** | P0 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 0.25 day |

**What**  
Scan all new NuGet packages identified in SPEC-XXXX §9 before adding them to the project.

**Acceptance Criteria**
- [ ] OWASP Dependency-Check run — zero CRITICAL CVEs
- [ ] Trivy scan — zero HIGH/CRITICAL findings
- [ ] All packages version-pinned in `.csproj`
- [ ] Scan report artifact stored in repo `security/dependency-scans/`

**Constitution Ref**: §VIII.2 Gate 2

---

## Phase 1 — Keycloak Configuration 🔒

---

### TASK-XXXX-010 · Register Keycloak Client 🔒🔴

| Field | Value |
|---|---|
| **Priority** | P0 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 0.5 day |
| **Reviewer** | IAM Architect + Security Reviewer |
| **Branch** | `feature/SPEC-XXXX-keycloak-client` |

**What**  
Create the Keycloak client for this feature as Infrastructure-as-Code (JSON export or Terraform). Apply Client Policy profile.

**Steps**
1. Create client in Keycloak dev realm via console
2. Export realm config to `infra/keycloak/realms/[realm]-[feature].json`
3. Verify Client Policy enforcer attributes are applied (PKCE, DPoP, PAR, PS256)
4. Set `access_token_lifespan = 300`, `refresh_token_max_reuse = 0`
5. Configure back-channel and front-channel logout URIs
6. Commit config; verify CI applies it to staging via pipeline

**Acceptance Criteria**
- [ ] Client Policy compliance checklist (PLAN-XXXX §3.1) fully checked
- [ ] Config stored as code — no manual-only console state
- [ ] CI pipeline applies config to staging successfully
- [ ] IAM Architect PR approval

**Constitution Ref**: §II.1, §II.4, Appendix A

---

### TASK-XXXX-011 · Configure UMA 2.0 Resource Server & Policies 🔒🔴

| Field | Value |
|---|---|
| **Priority** | P0 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 1 day |
| **Reviewer** | IAM Architect + Security Reviewer |
| **Depends On** | TASK-XXXX-010 |

**What**  
Register resource server, define resources, scopes, and authorization policies in Keycloak per PLAN-XXXX §3.2.

**Steps**
1. Enable Authorization Services on the client
2. Define resources per spec §6.3
3. Create scope-based and role-based policies
4. Set permission strategy to **UNANIMOUS**
5. Test policy evaluation via Keycloak Authorization Evaluate tool
6. Export and commit updated realm config

**Acceptance Criteria**
- [ ] Resource `GET /v1/[resource]/*` with scope `read` — accessible by correct role ✅
- [ ] Resource `POST /v1/[resource]` with scope `write` — blocked for read-only role ✅
- [ ] Cross-user resource access rejected (BOLA prevention test) ✅
- [ ] UNANIMOUS strategy confirmed in policy config

**Constitution Ref**: §II.5

---

### TASK-XXXX-012 · Configure Authentication Flow & Step-Up 🔒🔴

| Field | Value |
|---|---|
| **Priority** | P0 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 1 day |
| **Reviewer** | IAM Architect |
| **Depends On** | TASK-XXXX-010 |

**What**  
Configure the authentication flow including MFA requirements, step-up triggers, and ACR mapping per PLAN-XXXX §3.3.

**Steps**
1. Create / modify authentication flow (copy base flow — never edit built-in)
2. Add WebAuthn Authenticator step (required, not optional)
3. Configure TOTP as alternative second factor
4. Define step-up authentication sub-flow for sensitive scopes
5. Map ACR levels (`acr1`, `acr2`, `acr3`) to flow steps
6. Test: login without MFA → blocked; login with WebAuthn → succeeds

**Acceptance Criteria**
- [ ] Login without MFA factor → rejected
- [ ] Step-up correctly triggered for sensitive scope
- [ ] ACR claim present in issued token with correct value
- [ ] CIBA push flow tested (if applicable per spec)

**Constitution Ref**: §II.3

---

## Phase 2 — .NET API Foundation 🔴

---

### TASK-XXXX-020 · JWT Bearer & DPoP Middleware Setup 🔴⚡

| Field | Value |
|---|---|
| **Priority** | P0 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 1 day |
| **Reviewer** | Security Reviewer |
| **Branch** | `feature/SPEC-XXXX-auth-middleware` |

**What**  
Configure JWT Bearer authentication with strict validation parameters and implement DPoP validation middleware per PLAN-XXXX §4.2 and §4.3.

**Steps**
1. Add `AddJwtBearer` with authority, audience, `ValidAlgorithms = ["PS256","ES256"]`, `ClockSkew = Zero`
2. Implement `DpopValidationMiddleware`:
   - Validate `DPoP` header presence
   - Verify proof JWT signature via `cnf.jkt` from access token
   - Verify `htm`, `htu`, `iat` freshness (≤ 60s)
   - Verify server-issued nonce (if active)
   - Reject → 401 with `WWW-Authenticate: DPoP error="invalid_dpop_proof"`
3. Register middleware **before** `UseAuthentication()`
4. Unit tests for all DPoP rejection scenarios

**Acceptance Criteria**
- [ ] RS256 token → 401 (algorithm rejected)
- [ ] Expired token (`ClockSkew = Zero`) → 401
- [ ] Missing `aud` → 401
- [ ] Valid token without DPoP header → 401
- [ ] Invalid DPoP `htm` → 401
- [ ] Stale DPoP `iat` (> 60s) → 401
- [ ] Valid token + valid DPoP proof → passes to next middleware

**Constitution Ref**: §III.1, §II.4

---

### TASK-XXXX-021 · Token Replay Prevention (`jti` Cache) 🔴

| Field | Value |
|---|---|
| **Priority** | P0 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 0.5 day |
| **Reviewer** | Security Reviewer |
| **Depends On** | TASK-XXXX-020 |

**What**  
Implement `TokenReplayMiddleware` that checks `jti` claim against Redis on every authenticated request.

**Steps**
1. After JWT validation: extract `jti` from token
2. `GET replay:jti:{value}` from Redis
3. If exists → log `SecurityEvent.TokenReplay`, return 401, emit SIEM alert
4. If not exists → `SET replay:jti:{value} "" EX {token_remaining_ttl}` (atomic)
5. Unit test: first request passes, second identical request fails

**Acceptance Criteria**
- [ ] First request with valid `jti` → passes
- [ ] Second request with same `jti` → 401 immediately
- [ ] Redis key TTL = remaining token lifetime (verified)
- [ ] SIEM event `SecurityEvent.TokenReplay` fired on replay attempt

**Constitution Ref**: §III.1, §VI.2

---

### TASK-XXXX-022 · ACR Enforcement Middleware 🔴

| Field | Value |
|---|---|
| **Priority** | P0 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 0.5 day |
| **Reviewer** | Security Reviewer |
| **Depends On** | TASK-XXXX-020 |

**What**  
Implement `AcrValidationMiddleware` (or `IAuthorizationRequirement`) that rejects tokens with insufficient `acr` values for the requested endpoint.

**Steps**
1. Define `AcrRequirement(string minimumAcr)`
2. Implement `AcrAuthorizationHandler` — compare token `acr` claim against requirement
3. Return 401 with `WWW-Authenticate: Bearer error="insufficient_user_authentication"` on failure
4. Register in Authorization policies per spec

**Acceptance Criteria**
- [ ] Token with `acr = "acr1"` rejected on endpoint requiring `acr2`
- [ ] Token with `acr = "acr2"` accepted on endpoint requiring `acr2`
- [ ] Correct `WWW-Authenticate` header returned on failure (step-up hint)

**Constitution Ref**: §II.3, §III.2

---

## Phase 3 — Feature Implementation

---

### TASK-XXXX-030 · Domain Model & Aggregate 

| Field | Value |
|---|---|
| **Priority** | P1 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | X days |
| **Reviewer** | Tech Lead |
| **Depends On** | Phase 2 complete |

**What**  
Implement the domain model per Spec §3.3.

**Steps**
1. Define aggregate root with value objects
2. Business rules as domain invariants (throw on violation — never return null for invalid state)
3. Domain events for state changes (audit trail feed)
4. Unit tests: invariant enforcement, valid state transitions

**Acceptance Criteria**
- [ ] Domain model enforces all invariants
- [ ] PII fields identified and marked for encryption at infrastructure layer
- [ ] No direct dependency on EF Core or HTTP concerns
- [ ] Unit test coverage ≥ 90% on invariant logic

---

### TASK-XXXX-031 · Application Commands & Queries

| Field | Value |
|---|---|
| **Priority** | P1 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | X days |
| **Reviewer** | Tech Lead |
| **Depends On** | TASK-XXXX-030 |

**What**  
Implement CQRS commands and queries. Each handler enforces **BOLA** — users can only operate on resources they own/are authorized for.

**Steps**
1. Define command/query records
2. Implement handlers with explicit ownership check (`sub` from token matches resource owner)
3. FluentValidation validators for each command/query input
4. Integration tests covering authorization paths (see S-04 BOLA scenario)

**Acceptance Criteria**
- [ ] BOLA test: handler rejects access when `sub` doesn't match resource owner
- [ ] All inputs validated before handler logic executes
- [ ] No entity returned directly — mapped to response DTO via explicit mapper
- [ ] Audit log event fired for every state change

---

### TASK-XXXX-032 · Controller & Endpoint Definition 🔴

| Field | Value |
|---|---|
| **Priority** | P1 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 0.5 day |
| **Reviewer** | Security Reviewer |
| **Depends On** | TASK-XXXX-022, TASK-XXXX-031 |

**What**  
Define the API controller with security attributes and rate limiting per Spec §3.2 and PLAN-XXXX §4.4.

**Steps**
1. Define controller with `[Authorize(Policy = "...")]` on every action
2. Apply rate limiting attributes per spec §4.1
3. Return `ProblemDetails` for all error paths (RFC 7807)
4. Add `Deprecation`/`Sunset` headers if endpoint versions an existing route
5. Verify OpenAPI annotation is correct and complete

**Acceptance Criteria**
- [ ] No `[AllowAnonymous]` present
- [ ] Every action has an explicit `[Authorize]` policy
- [ ] Rate limit attribute applied
- [ ] Error responses are `ProblemDetails` — no stack traces in any environment
- [ ] OpenAPI spec generated correctly

**Constitution Ref**: §III.2, §III.3, §IX.3

---

### TASK-XXXX-033 · Database Migration

| Field | Value |
|---|---|
| **Priority** | P1 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 0.5 day |
| **Reviewer** | Tech Lead |
| **Depends On** | TASK-XXXX-030 |

**What**  
Create EF Core migration per PLAN-XXXX §5.1. Verify migration is reversible.

**Steps**
1. `dotnet ef migrations add [DescriptiveName]`
2. Review generated SQL — verify no raw string interpolation
3. Add index definitions as required
4. Test down migration in dev environment
5. Verify PII column encryption at application layer

**Acceptance Criteria**
- [ ] Migration applies cleanly in dev and staging
- [ ] Down migration reverts without data loss (in test environment)
- [ ] No sensitive data stored in plaintext (PII columns encrypted at application layer)
- [ ] Index strategy reviewed for query performance

---

## Phase 4 — Testing 🧪

---

### TASK-XXXX-040 · Security Integration Tests 🧪🔴

| Field | Value |
|---|---|
| **Priority** | P0 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 2 days |
| **Reviewer** | Security Reviewer |
| **Depends On** | Phase 2, Phase 3 complete |

**What**  
Implement all S-XX security test scenarios from PLAN-XXXX §8.1 as automated integration tests.

**Test Scenarios to implement**

| Scenario | Status |
|---|---|
| S-01: Expired access token → 401 | ☐ |
| S-02: Invalid DPoP proof → 401 | ☐ |
| S-03: Replayed `jti` → 401 | ☐ |
| S-04: BOLA — User A accesses User B resource → 403 | ☐ |
| S-05: Insufficient ACR → 401 + step-up hint | ☐ |
| S-06: Mass assignment — extra fields ignored | ☐ |
| S-07: Rate limit exceeded → 429 | ☐ |
| S-08: SQL injection in param → 400 | ☐ |
| S-09: RS256 token → 401 | ☐ |
| S-10: Missing `aud` → 401 | ☐ |
| S-11: Missing scope → 403 | ☐ |
| S-12: HTTP (non-TLS) → rejected | ☐ |

**Acceptance Criteria**
- [ ] All 12 scenarios automated and passing in CI
- [ ] Tests use a real Keycloak test instance (not mocked tokens)
- [ ] Each test verifies response body is RFC 7807 ProblemDetails (no internal detail)

---

### TASK-XXXX-041 · Unit Test Suite 🧪

| Field | Value |
|---|---|
| **Priority** | P1 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 1.5 days |
| **Reviewer** | Tech Lead |
| **Depends On** | Phase 3 complete |

**What**  
Unit test domain logic, validators, mappers, and middleware in isolation.

**Acceptance Criteria**
- [ ] Coverage ≥ 90% on security-critical paths (auth, validation, authorization handlers)
- [ ] Coverage ≥ 80% overall
- [ ] Every FluentValidation rule has at least one passing and one failing test case
- [ ] Domain invariant violations covered
- [ ] Response DTO mapper tests: all fields covered — new field fails test until mapped

---

### TASK-XXXX-042 · Load & Performance Test 🧪

| Field | Value |
|---|---|
| **Priority** | P1 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 0.5 day |
| **Reviewer** | Tech Lead |
| **Depends On** | Staging deployment ready |

**What**  
Run k6 load test against staging environment to verify performance targets from Spec §4.2.

**Acceptance Criteria**
- [ ] p99 latency ≤ target under sustained load
- [ ] Error rate < 0.1% at target throughput
- [ ] Rate limiter triggers correctly under overload (429 returned, not 500)
- [ ] No memory leaks observed over 10-minute soak test
- [ ] k6 report committed to `tests/performance/results/`

---

## Phase 5 — Observability & SIEM 🔧

---

### TASK-XXXX-050 · OTel Instrumentation 🔧

| Field | Value |
|---|---|
| **Priority** | P1 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 0.5 day |
| **Reviewer** | Operations |
| **Depends On** | Phase 3 complete |

**What**  
Add OpenTelemetry spans and metrics per PLAN-XXXX §6.1 and §6.2.

**Steps**
1. Add custom spans for I/O operations (DB, Redis, Keycloak introspection)
2. Add counters: `requests_total`, `auth_failures_total` with labels
3. Add histogram: `request_duration_seconds`
4. Verify `correlationId` (W3C `traceparent`) propagated in all log entries
5. Verify trace visible end-to-end in staging tracing backend

**Acceptance Criteria**
- [ ] Traces visible from API Gateway → .NET API → DB in tracing tool
- [ ] `sub` and `correlationId` present in every log line (no PII beyond opaque ID)
- [ ] Metrics visible in Prometheus / Grafana dashboard

---

### TASK-XXXX-051 · SIEM Alert Rules 🔧🔴

| Field | Value |
|---|---|
| **Priority** | P0 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 0.5 day |
| **Reviewer** | Security Reviewer |
| **Depends On** | TASK-XXXX-050 |

**What**  
Deploy SIEM alert rules for security events from PLAN-XXXX §6.3.

**Steps**
1. Write SIEM rule for `auth_failures_total > 5/min from same IP`
2. Write SIEM rule for `SecurityEvent.TokenReplay` → P1 incident
3. Write SIEM rule for policy denial spike
4. Verify alerts fire via synthetic event injection in staging
5. Connect alerts to on-call rotation

**Acceptance Criteria**
- [ ] All alert rules from PLAN-XXXX §6.3 deployed
- [ ] Each alert verified with synthetic event — fires within 60 seconds
- [ ] Alert severity correctly mapped (token replay → P1, auth failures → P2)
- [ ] No alert fires on normal traffic (false positive test)

---

## Phase 6 — Documentation & Rollout 📄

---

### TASK-XXXX-060 · OpenAPI Spec Update 📄

| Field | Value |
|---|---|
| **Priority** | P1 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 0.25 day |

**What**  
Ensure OpenAPI 3.1 spec is complete, accurate, and committed. CI route-audit step must confirm no undocumented routes.

**Acceptance Criteria**
- [ ] All new endpoints documented with request/response schemas
- [ ] Security schemes documented (`bearerAuth`, `dpop`)
- [ ] Required scopes and ACR documented per endpoint
- [ ] CI route-audit step passes (zero undocumented routes)
- [ ] API changelog entry added

---

### TASK-XXXX-061 · Operational Runbook 📄

| Field | Value |
|---|---|
| **Priority** | P2 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 0.25 day |

**What**  
Write operational runbook covering common support scenarios and incident response for this feature.

**Contents**
- [ ] How to rotate Keycloak client secret for this client
- [ ] How to revoke all sessions for a user
- [ ] How to disable the feature (feature flag procedure)
- [ ] How to roll back the DB migration
- [ ] How to diagnose token replay alerts

---

### TASK-XXXX-062 · Spec & Plan Status Update 📄

| Field | Value |
|---|---|
| **Priority** | P2 |
| **Status** | TODO |
| **Assignee** | |
| **Estimate** | 0.1 day |

**What**  
Update SPEC-XXXX status to `COMPLETED` and PLAN-XXXX status to `COMPLETED`. Archive threat model final state.

**Acceptance Criteria**
- [ ] SPEC-XXXX front-matter `Status: COMPLETED`
- [ ] PLAN-XXXX front-matter `Status: COMPLETED`
- [ ] Threat model final state committed to `security/threat-models/SPEC-XXXX-final.md`

---

## Blocked Tasks Log

| Task | Blocked By | Since | Resolution |
|---|---|---|---|
| | | | |

---

## Decisions Log

| Date | Decision | Rationale | Decided By |
|---|---|---|---|
| | | | |

---

## Task Completion Checklist

Before marking this TASK file as `COMPLETED`, verify all of the following:

```
PRE-CODE
[ ] TASK-XXXX-001  Threat model signed off
[ ] TASK-XXXX-002  Keycloak config design approved
[ ] TASK-XXXX-003  Dependency audit clean

KEYCLOAK
[ ] TASK-XXXX-010  Client registered as IaC
[ ] TASK-XXXX-011  UMA 2.0 policies configured
[ ] TASK-XXXX-012  Auth flow + step-up configured

API FOUNDATION
[ ] TASK-XXXX-020  JWT + DPoP middleware
[ ] TASK-XXXX-021  Token replay (jti cache)
[ ] TASK-XXXX-022  ACR enforcement

FEATURE
[ ] TASK-XXXX-030  Domain model
[ ] TASK-XXXX-031  Commands & queries (BOLA-safe)
[ ] TASK-XXXX-032  Controller (all [Authorize] policies applied)
[ ] TASK-XXXX-033  DB migration (reversible)

TESTING
[ ] TASK-XXXX-040  Security integration tests (all 12 S-XX pass)
[ ] TASK-XXXX-041  Unit tests (≥90% security paths)
[ ] TASK-XXXX-042  Load test (p99 target met)

OBSERVABILITY
[ ] TASK-XXXX-050  OTel instrumentation
[ ] TASK-XXXX-051  SIEM alert rules deployed + verified

DOCS
[ ] TASK-XXXX-060  OpenAPI spec committed
[ ] TASK-XXXX-061  Runbook written
[ ] TASK-XXXX-062  Spec/Plan status updated

CI GATES (all 9 must be green)
[ ] Gate 1  SAST — zero HIGH/CRITICAL
[ ] Gate 2  Dependency scan — zero CRITICAL CVEs
[ ] Gate 3  Secrets scan — clean
[ ] Gate 4  Test coverage — ≥90% security paths
[ ] Gate 5  DAST — zero HIGH
[ ] Gate 6  IaC scan — zero HIGH
[ ] Gate 7  Container scan — zero HIGH/CRITICAL
[ ] Gate 8  SBOM generated + signed
[ ] Gate 9  Image signatures verified
```