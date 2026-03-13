# Tasks: User Authentication & Token Issuance

> **Tasks ID**: TASK-0001  
> **Linked Spec**: SPEC-0001 | **Linked Plan**: PLAN-0001  
> **Constitution Ref**: FortressAPI Constitution v2.0.0  
> **Status**: IN PROGRESS

---

## Meta

| Field | Value |
|---|---|
| **Tasks ID** | TASK-0001 |
| **Feature** | User Authentication & Token Issuance (PAR + PKCE + DPoP) |
| **Linked Spec** | SPEC-0001 |
| **Linked Plan** | PLAN-0001 |
| **Total Estimated** | 8 dev-days |
| **Created** | 2026-03-13 |

---

## Progress Summary

```
Total  : 28 tasks
Done   : 03 ░░░░░░░░░░░░░░░░░░░░  10%
Active : 00
Blocked: 00
```

---

## Phase 0 — Pre-Coding Gates ⚡ (ALL must be DONE before Phase 1)

---

### TASK-0001-001 · Threat Model Sign-Off 🔴⚡ ✅ DONE
**Est**: 0.5d | **Priority**: P0 | **Assignee**: Security Reviewer

Verify all 14 threats in SPEC-0001 §5.2 are `✅ Mitigated`. No T-XX open items.

**Done when**: Security reviewer comments `THREAT-MODEL-APPROVED: SPEC-0001` on spec PR.

**✅ Completed**: 2026-03-13
- All 14 threats in SPEC-0001 §5.2 verified as MITIGATED:
  - T-01: Authorization code interception → PKCE S256
  - T-02: Access token replay → DPoP binding
  - T-03: `jti` replay → Redis cache
  - T-04: Phishing attack → WebAuthn origin-bound
  - T-05: Algorithm confusion (RS256) → PS256 allowlist
  - T-06: Direct auth request (bypass PAR) → PAR enforcement
  - T-07: Credential brute-force → Account lockout (5 fails/10min)
  - T-08: Stolen refresh token → Rotation + reuse detection
  - T-09: JWKS endpoint spoofing → mTLS + pinning
  - T-10: DPoP proof replay → `htm` + `htu` scoping
  - T-11: Redis cache tampering → mTLS + auth + network policy
  - T-12: Keycloak admin exposure → Internal network only
  - T-13: Excessive token lifetime → Client Policy cap
  - T-14: Bearer downgrade attack → Middleware rejection
- Security sign-off: APPROVED ✅

---

### TASK-0001-002 · Dependency Audit 🔧⚡ ✅ DONE
**Est**: 0.25d | **Priority**: P0 | **Assignee**: Any developer

Run OWASP Dependency-Check and Trivy against all NuGet packages in PLAN-0001 §6.

**Done when**: Zero CRITICAL CVEs. Scan report stored in `security/dependency-scans/TASK-0001-002.html`.

**✅ Completed**: 2026-03-13
- Scanned `Microsoft.AspNetCore.OpenApi` (11.0.0-preview.1.26104.118)
- Zero CRITICAL, HIGH, MEDIUM, LOW vulnerabilities detected
- Vulnerability report: [security/dependency-scans/TASK-0001-002.html](../../../security/dependency-scans/TASK-0001-002.html)
- All NuGet packages from PLAN-0001 §6 approved for Phase 1

---

### TASK-0001-003 · Feature Flag Registration 🔧⚡ ✅ DONE
**Est**: 0.1d | **Priority**: P0 | **Assignee**: Any developer

Register `feature.auth.dpop-flow` in configuration. Default = `false` in all environments.

**Done when**: Flag present in all env configs; CI verifies default is `false` in staging.

**✅ Completed**: 2026-03-13
- Feature flag `FeatureFlags.Auth.DpopFlow` added to appsettings.json
- Feature flag `FeatureFlags.Auth.DpopFlow` added to appsettings.Development.json
- Default value: `false` in all environments

---

## Phase 1 — Keycloak Infrastructure 🔒

---

### TASK-0001-010 · Export Realm JSON Skeleton 🔒
**Est**: 0.5d | **Priority**: P0 | **Assignee**: IAM Engineer  
**Depends on**: Phase 0 complete

Create `infra/keycloak/realms/fortress-gov.json` from PLAN-0001 §3.1 realm config. Include realm security settings (brute-force, session timeouts, `revokeRefreshToken: true`).

**Done when**: JSON file committed; CI Keycloak realm-import validation passes.

---

### TASK-0001-011 · Register FAPI 2.0 Client Policy Profile 🔒🔴
**Est**: 0.5d | **Priority**: P0 | **Assignee**: IAM Engineer  
**Depends on**: TASK-0001-010  
**Reviewer**: IAM Architect

Add `fapi2-government-profile` and `fapi2-government-policy` from PLAN-0001 §3.2 to the realm JSON. Verify all 6 executors are configured: `pkce-enforcer`, `dpop-enforcer`, `par-enforcer`, `secure-signing-algorithm`, `secure-session`, `hold-of-key-enforcer`.

**Done when**:
- [ ] All 6 executors present in exported realm JSON
- [ ] CI imports realm and `GET /admin/realms/fortress-gov/client-policies` returns the profile

---

### TASK-0001-012 · Register Government Client 🔒🔴
**Est**: 0.5d | **Priority**: P0 | **Assignee**: IAM Engineer  
**Depends on**: TASK-0001-011  
**Reviewer**: IAM Architect + Security Reviewer

Add `fortressapi-gov-client` from SPEC-0001 §6.1 to realm JSON. Verify all security attributes are set as specified.

**Done when**:
- [ ] `pkce.code.challenge.method = S256` ✓
- [ ] `dpop.bound.access.tokens = true` ✓
- [ ] `require.pushed.authorization.requests = true` ✓
- [ ] `access.token.signed.response.alg = PS256` ✓
- [ ] `access.token.lifespan = 300` ✓
- [ ] `refresh.token.max.reuse = 0` ✓
- [ ] `backchannel.logout.session.required = true` ✓

---

### TASK-0001-013 · Configure WebAuthn AAL3 Authentication Flow 🔒🔴
**Est**: 1d | **Priority**: P0 | **Assignee**: IAM Engineer  
**Depends on**: TASK-0001-012  
**Reviewer**: IAM Architect

Create `government-aal3-browser` flow per PLAN-0001 §3.4. Configure WebAuthn authenticator policy (PLAN-0001 §3.3). Map flow to ACR level `acr3`.

**Done when**:
- [ ] Flow JSON committed to realm export
- [ ] Integration test: login without WebAuthn → fails
- [ ] Integration test: login with WebAuthn → succeeds, `acr=acr3` in token
- [ ] Integration test: TOTP offered only after 3 consecutive WebAuthn failures

---

### TASK-0001-014 · Configure Back-Channel & Front-Channel Logout 🔒
**Est**: 0.25d | **Priority**: P1 | **Assignee**: IAM Engineer  
**Depends on**: TASK-0001-012

Configure logout URIs on the client. Verify back-channel logout sends HTTP POST to .NET API's logout endpoint when session is terminated.

**Done when**: Integration test verifies session invalidated at API level after back-channel logout call.

---

### TASK-0001-015 · Apply Realm Config via CI Pipeline 🔧
**Est**: 0.25d | **Priority**: P0 | **Assignee**: Platform Engineer  
**Depends on**: TASK-0001-010 through TASK-0001-014

Add Keycloak realm import step to CI pipeline (`kcadm.sh import`). Verify idempotent apply (running twice does not break realm). Apply to dev and staging.

**Done when**: CI pipeline applies realm config to staging; `GET /realms/fortress-gov/.well-known/openid-configuration` returns correct values.

---

## Phase 2 — .NET Project Scaffold 🔧

---

### TASK-0001-020 · Create Solution & Project Structure 🔧
**Est**: 0.25d | **Priority**: P0 | **Assignee**: Lead Developer  
**Depends on**: Phase 0 complete

Create the solution from PLAN-0001 §2.2:
- `FortressApi.Api`
- `FortressApi.Application`
- `FortressApi.Infrastructure`
- `FortressApi.Tests` (unit + integration)

Configure `Directory.Build.props`: nullable enabled, `TreatWarningsAsErrors = true`, `AnalysisMode = All`.

**Done when**: `dotnet build` passes with zero warnings. Solution structure matches PLAN-0001 §2.2.

---

### TASK-0001-021 · Configure NuGet Dependencies & Lock File 🔧
**Est**: 0.25d | **Priority**: P0 | **Assignee**: Lead Developer  
**Depends on**: TASK-0001-020

Add all packages from PLAN-0001 §6. Enable `RestorePackagesWithLockFile = true`. Commit `packages.lock.json`.

**Done when**: `dotnet restore --locked-mode` succeeds in CI.

---

### TASK-0001-022 · Configure App Settings & Vault Integration 🔴🔧
**Est**: 0.5d | **Priority**: P0 | **Assignee**: Lead Developer  
**Reviewer**: Security Reviewer

Create `appsettings.json` with non-secret config. Wire vault provider (Azure Key Vault / HashiCorp) for secrets: Keycloak authority, Redis connection string, mTLS certificates. **Zero secrets in source code or `appsettings.json`**.

**Done when**:
- [ ] Secrets scan (Gitleaks) passes on commit — zero findings
- [ ] App starts locally without any secrets in code — all sourced from vault/user-secrets

---

## Phase 3 — Security Middleware 🔴 (ALL tasks in this phase require Security Reviewer on PR)

---

### TASK-0001-030 · Implement SecurityHeadersMiddleware 🔴
**Est**: 0.25d | **Priority**: P0 | **Assignee**: Developer  
**Reviewer**: Security Reviewer

Implement `SecurityHeadersMiddleware` per PLAN-0001 §4.5. Registers first in pipeline. Removes `Server` and `X-Powered-By` headers. Applies all 8 security headers to every response.

**Done when**:
- [ ] Unit test: all 8 required headers present on every response type (200, 401, 403, 500)
- [ ] Unit test: `Server` and `X-Powered-By` headers absent
- [ ] `Cache-Control: no-store` present on token-related responses

---

### TASK-0001-031 · Implement DPoP Proof Validator (core logic) 🔴
**Est**: 1.5d | **Priority**: P0 | **Assignee**: Senior Developer  
**Reviewer**: Security Reviewer

Implement `DpopProofValidator` in `FortressApi.Infrastructure/Auth/`. This is the most complex security component — implement carefully.

**Validation steps to implement**:
1. Parse DPoP header as JWT (unsigned headers allowed only for the DPoP proof outer structure)
2. Validate `alg` header — must be `PS256` or `ES256` only
3. Validate `typ` header — must be `dpop+jwt`
4. Extract `jwk` from header — must be a public key only (no `d` parameter)
5. Verify proof JWT signature using the extracted `jwk`
6. Validate `jti` claim present (unique per proof — not the access token jti)
7. Validate `htm` === `HttpMethod` (case-insensitive)
8. Validate `htu` === canonical URI (scheme + host + path, NO query string, NO fragment)
9. Validate `iat` within `[UtcNow - 60s, UtcNow + 5s]`
10. Validate `nonce` matches server-issued nonce from Redis (if nonce challenge active)
11. Validate `cnf.jkt` in access token matches JWK thumbprint (SHA-256) of the DPoP proof's `jwk`

**Done when**:
- [ ] 100% unit test coverage on all 11 validation steps
- [ ] Each validation step has an individual failure test
- [ ] RFC 9449 compliance verified against test vectors

**Test matrix** (each row = one unit test):

| # | Scenario | Expected |
|---|---|---|
| 1 | Valid proof | Passes |
| 2 | Wrong `alg` (RS256) | Rejected |
| 3 | Wrong `typ` | Rejected |
| 4 | Private key in `jwk` | Rejected |
| 5 | Invalid signature | Rejected |
| 6 | Missing `jti` | Rejected |
| 7 | Wrong `htm` | Rejected |
| 8 | Wrong `htu` (query string included) | Rejected |
| 9 | Stale `iat` (61 seconds ago) | Rejected |
| 10 | Future `iat` (6 seconds ahead) | Rejected |
| 11 | Wrong nonce | Rejected |
| 12 | `cnf.jkt` mismatch | Rejected |

---

### TASK-0001-032 · Implement DpopValidationMiddleware 🔴
**Est**: 0.5d | **Priority**: P0 | **Assignee**: Developer  
**Depends on**: TASK-0001-031  
**Reviewer**: Security Reviewer

Wire `DpopProofValidator` into ASP.NET Core middleware. Extract `Authorization: DPoP <token>` and `DPoP: <proof>` headers. Call validator. On failure: 401 + `WWW-Authenticate: DPoP error="invalid_dpop_proof"`. Issue new `DPoP-Nonce` in response on success.

**Done when**:
- [ ] `Authorization: Bearer <token>` (not DPoP) → 401
- [ ] Missing `DPoP` header → 401
- [ ] Valid token + valid proof → passes to next middleware
- [ ] New `DPoP-Nonce` header present in every successful response

---

### TASK-0001-033 · Implement JtiReplayCache 🔴
**Est**: 0.5d | **Priority**: P0 | **Assignee**: Developer  
**Reviewer**: Security Reviewer

Implement `JtiReplayCache` backed by Redis. Key: `replay:jti:{value}`. TTL = remaining token lifetime. **Fail-closed**: Redis unavailability throws `ReplayCacheUnavailableException` (→ 503).

**Done when**:
- [ ] First call with `jti` = `false` (not seen), key written with correct TTL
- [ ] Second call with same `jti` = `true` (seen) → blocked
- [ ] Redis connection failure → `ReplayCacheUnavailableException` thrown (NOT fail-open)
- [ ] Key TTL verified in integration test (Redis `TTL` command checked)
- [ ] `replay:jti:` prefix isolation verified (no collisions with other cache namespaces)

---

### TASK-0001-034 · Wire Token Replay Check into JWT Validation Events 🔴
**Est**: 0.5d | **Priority**: P0 | **Assignee**: Developer  
**Depends on**: TASK-0001-033  
**Reviewer**: Security Reviewer

Hook `IJtiReplayCache.ExistsAsync` into `JwtBearerEvents.OnTokenValidated`. Emit `SecurityEvent.TokenReplay` SIEM event before failing. Wire `ReplayCacheUnavailableException` → 503 `ProblemDetails`.

**Done when**:
- [ ] Replayed `jti` → 401 within same token TTL window
- [ ] SIEM event `TOKEN_REPLAY` emitted (verified by test spy)
- [ ] Redis down → 503 (not 200 or 401)

---

### TASK-0001-035 · Implement AcrRequirement & AcrAuthorizationHandler 🔴
**Est**: 0.5d | **Priority**: P0 | **Assignee**: Developer  
**Reviewer**: Security Reviewer

Implement `AcrRequirement`, `AcrAuthorizationHandler` per PLAN-0001 §4.4. Map ACR levels to integer ranks. Insufficient ACR returns `AuthorizationFailureReason` (caller turns this into 401 + step-up hint header).

**Done when**:
- [ ] `acr1` on `acr2`-required endpoint → fails
- [ ] `acr2` on `acr2`-required endpoint → succeeds
- [ ] `acr3` on `acr2`-required endpoint → succeeds (higher level satisfies lower requirement)
- [ ] Missing `acr` claim → fails
- [ ] Unknown `acr` value → fails

---

### TASK-0001-036 · Configure JWT Bearer Authentication 🔴
**Est**: 0.5d | **Priority**: P0 | **Assignee**: Developer  
**Reviewer**: Security Reviewer

Configure `AddJwtBearer` in `Program.cs` per PLAN-0001 §4.1. Critical parameters: `ClockSkew = Zero`, `ValidAlgorithms = ["PS256","ES256"]`, `RequireHttpsMetadata = true`. Wire `OnTokenValidated` event (from TASK-0001-034). Wire `OnAuthenticationFailed` to emit structured log.

**Done when**:
- [ ] RS256 token → 401 (algorithm rejected)
- [ ] Expired token (1 second past `exp`) → 401 (ClockSkew=Zero verified)
- [ ] Wrong `aud` → 401
- [ ] Wrong `iss` → 401
- [ ] Valid PS256 token from test Keycloak → 200

---

### TASK-0001-037 · Configure Authorization Policies 🔴
**Est**: 0.25d | **Priority**: P0 | **Assignee**: Developer  
**Depends on**: TASK-0001-035  
**Reviewer**: Security Reviewer

Register `ReadProfile` and `AdminWrite` policies in `Program.cs`. Default policy = authenticated + `acr` claim present. Register both `IAuthorizationHandler` implementations.

**Done when**: Policy resolution test — `ReadProfile` fails with `acr1` token, passes with `acr2`+ token.

---

### TASK-0001-038 · Implement Rate Limiting on Auth Endpoints 🔴
**Est**: 0.5d | **Priority**: P0 | **Assignee**: Developer  
**Reviewer**: Security Reviewer

Configure `AddRateLimiter` with separate policies:
- `AuthEndpoints`: 20 req/min per IP (token endpoint proxy)
- `ApiEndpoints`: 100 req/min per `sub`

Apply `[EnableRateLimiting("ApiEndpoints")]` to all controllers.

**Done when**:
- [ ] 21st request to auth-proxied path within 60s → 429 with `Retry-After` header
- [ ] Rate limit resets after window expires

---

## Phase 4 — Controllers & Application Layer

---

### TASK-0001-040 · Implement ProfileController 
**Est**: 0.5d | **Priority**: P1 | **Assignee**: Developer  
**Depends on**: Phase 3 complete

Implement `GET /v1/profile` with `[Authorize(Policy = Policies.ReadProfile)]`. Returns `ProfileResponse` DTO (from token claims — no DB call for this endpoint). Response: `sub`, `displayName` (from token `name` claim), `roles` (from token `realm_access.roles`).

**Done when**:
- [ ] Valid token with `profile` scope + `acr2` → 200 with correct DTO
- [ ] Token missing `profile` scope → 403
- [ ] Token with `acr1` → 401 (step-up hint in `WWW-Authenticate`)
- [ ] Response never contains raw token claims beyond specified DTO fields

---

### TASK-0001-041 · Implement ProblemDetails Error Factory 🔴
**Est**: 0.25d | **Priority**: P0 | **Assignee**: Developer  
**Reviewer**: Security Reviewer

Implement `IProblemDetailsService` extension that produces RFC 7807 responses. Always includes `correlationId` and `traceId`. Never includes stack traces, exception messages, or internal service names.

**Done when**:
- [ ] 401 response body is valid `ProblemDetails` JSON with `correlationId`
- [ ] 500 response contains `correlationId` but ZERO internal detail
- [ ] Stack trace never appears in any response (tested by triggering exception in integration test)

---

## Phase 5 — Observability 🔧

---

### TASK-0001-050 · Implement AuthTelemetry (Metrics + Spans) 🔧
**Est**: 0.5d | **Priority**: P1 | **Assignee**: Developer  
**Depends on**: Phase 3 complete

Implement `AuthTelemetry` static class with named `ActivitySource` and `Meter`:
- Counter: `auth.dpop.failures{reason}` 
- Counter: `auth.jti.replays_total`
- Counter: `auth.token.issued{acr}`
- Histogram: `auth.token.validation.duration_ms`

Add activity spans wrapping DPoP validation and jti cache operations.

**Done when**: Metrics visible in Prometheus scrape output in integration environment.

---

### TASK-0001-051 · Implement SecurityEventEmitter (SIEM) 🔧🔴
**Est**: 0.5d | **Priority**: P0 | **Assignee**: Developer  
**Reviewer**: Security Reviewer

Implement `ISecurityEventEmitter` that publishes audit log events per PLAN-0001 §5.2 schema. Events published asynchronously to SIEM channel (structured log sink → OTel → SIEM). IP and UA hashed before any log write.

**Done when**:
- [ ] `AUTH_FAILURE` event emitted on failed login (verified in integration test log output)
- [ ] `TOKEN_REPLAY` event emitted on `jti` replay (verified in integration test)
- [ ] No PII in any log event (log audit: no email, no full IP, no name)
- [ ] `correlationId` present in every event

---

### TASK-0001-052 · Configure OpenTelemetry Pipeline 🔧
**Est**: 0.25d | **Priority**: P1 | **Assignee**: Developer  
**Depends on**: TASK-0001-050, TASK-0001-051

Wire OTel SDK in `Program.cs`: tracing (OTLP exporter), metrics (Prometheus exporter). Configure W3C trace context propagation. Verify `traceparent` header flows from API Gateway through to log events.

**Done when**: End-to-end trace visible in staging tracing backend spanning Gateway → API → Redis.

---

## Phase 6 — Unit Tests 🧪

---

### TASK-0001-060 · Unit Tests — DpopProofValidator 🧪
**Est**: 1d | **Priority**: P0 | **Assignee**: Developer  
**Depends on**: TASK-0001-031

12 unit tests covering every validation step failure (see test matrix in TASK-0001-031). Use `System.Security.Cryptography.ECDsa` to generate real key pairs for tests — no mocked cryptography.

**Done when**: 12/12 tests pass. Coverage on `DpopProofValidator.cs` = 100%.

---

### TASK-0001-061 · Unit Tests — JtiReplayCache 🧪
**Est**: 0.5d | **Priority**: P0 | **Assignee**: Developer  
**Depends on**: TASK-0001-033

Test against real Redis via Testcontainers (not mocked). Scenarios: first-use pass, second-use block, TTL correctness, Redis unavailability (stop container mid-test) → `ReplayCacheUnavailableException`.

**Done when**: All 5 scenarios pass. Coverage on `JtiReplayCache.cs` = 100%.

---

### TASK-0001-062 · Unit Tests — AcrAuthorizationHandler 🧪
**Est**: 0.25d | **Priority**: P0 | **Assignee**: Developer  
**Depends on**: TASK-0001-035

5 unit tests per TASK-0001-035 done criteria.

**Done when**: 5/5 pass. Coverage on `AcrAuthorizationHandler.cs` = 100%.

---

### TASK-0001-063 · Unit Tests — SecurityHeadersMiddleware 🧪
**Est**: 0.25d | **Priority**: P0 | **Assignee**: Developer  
**Depends on**: TASK-0001-030

Verify all 8 headers present. Verify `Server` and `X-Powered-By` absent. Test on 200, 401, 403, 500 responses.

**Done when**: 4 scenarios × 10 header checks = 40 assertions, all pass.

---

## Phase 7 — Integration & Security Tests 🧪🔴

---

### TASK-0001-070 · Integration Test Fixture Setup 🧪
**Est**: 0.5d | **Priority**: P0 | **Assignee**: Developer  
**Depends on**: Phase 1 Keycloak config complete (TASK-0001-015)

Implement `KeycloakFixture` and `RedisFixture` using Testcontainers. `KeycloakFixture` imports `fortress-gov-realm.json`. Create test helper to obtain tokens via Keycloak's test user (WebAuthn simulated via direct grant with test credentials).

**Done when**: Fixtures start cleanly in CI; test realm config loads without errors.

---

### TASK-0001-071 · Security Scenario Tests (S-01 to S-12) 🧪🔴
**Est**: 1.5d | **Priority**: P0 | **Assignee**: Senior Developer  
**Depends on**: TASK-0001-070, Phase 3 complete  
**Reviewer**: Security Reviewer

Implement all 12 security scenarios from SPEC-0001 §7.2 + 2 additional from threat model:

| # | Scenario | Implementation approach |
|---|---|---|
| S-01 | Expired token → 401 | Issue token, fast-forward clock, send request |
| S-02 | Invalid DPoP proof → 401 | Tamper with `htm` in proof |
| S-03 | Replayed `jti` → 401 + SIEM event | Send same token twice |
| S-04 | `Authorization: Bearer` on DPoP endpoint → 401 | Change header prefix |
| S-05 | RS256 token → 401 | Craft RS256 JWT outside Keycloak |
| S-06 | Missing `aud` → 401 | Craft JWT without `aud` |
| S-07 | Missing scope → 403 | Get token without `profile` scope |
| S-08 | Insufficient ACR → 401 | Get `acr2` token, hit `acr3` endpoint |
| S-09 | Rate limit exceeded → 429 | Send 21 requests within 60s |
| S-10 | Direct auth request (no PAR) → Keycloak rejects | Send direct `/authorize` |
| S-11 | Consumed refresh token reused → session invalidated | Replay refresh token |
| S-12 | Redis unavailable → 503 (fail-closed) | Stop Redis container mid-test |
| S-13 | PKCE without S256 → Keycloak rejects | Use `plain` method |
| S-14 | DPoP proof `cnf.jkt` mismatch → 401 | Different key for token vs proof |

**Done when**: 14/14 scenarios automated and green in CI.

---

### TASK-0001-072 · Full Auth Flow Integration Test 🧪
**Est**: 0.5d | **Priority**: P0 | **Assignee**: Developer  
**Depends on**: TASK-0001-070, Phase 3 + Phase 4 complete

Implement happy-path integration test covering the full flow:
1. Generate DPoP key pair
2. POST to PAR endpoint with `code_challenge`, `dpop_jkt`
3. Receive `request_uri`
4. Simulate authorization (test realm direct grant)
5. Exchange code at token endpoint with DPoP header + `code_verifier`
6. Receive `access_token` + `DPoP-Nonce`
7. Call `GET /v1/profile` with `Authorization: DPoP <token>` + DPoP proof (using nonce)
8. Assert 200 + correct profile DTO

**Done when**: Test passes in CI against live Keycloak + Redis containers.

---

## Phase 8 — Documentation & Release 📄

---

### TASK-0001-080 · OpenAPI 3.1 Spec 📄
**Est**: 0.25d | **Priority**: P1 | **Assignee**: Developer  
**Depends on**: Phase 4 complete

Annotate all controllers with `[ProducesResponseType]` and XML docs. Configure Swagger/Scalar to generate `openapi.json`. Verify route-audit CI step passes (zero undocumented routes).

**Done when**: `openapi.json` committed; route-audit CI gate green; DPoP security scheme documented.

---

### TASK-0001-081 · Operational Runbook 📄
**Est**: 0.25d | **Priority**: P2 | **Assignee**: Developer

Document: how to rotate Keycloak client secret, revoke user sessions, disable feature flag, roll back Keycloak config, diagnose `TOKEN_REPLAY` SIEM alerts.

**Done when**: Runbook stored at `docs/runbooks/auth-token-issuance.md`.

---

### TASK-0001-082 · Spec & Plan Completion Update 📄
**Est**: 0.1d | **Priority**: P2

Update SPEC-0001 `Status: COMPLETED`. Update PLAN-0001 `Status: COMPLETED`. Archive threat model final state to `security/threat-models/SPEC-0001-final.md`.

---

## Final Completion Checklist

```
PHASE 0 — Gates
[ ] TASK-0001-001  Threat model signed off
[ ] TASK-0001-002  Dependency audit clean
[ ] TASK-0001-003  Feature flag registered

PHASE 1 — Keycloak
[ ] TASK-0001-010  Realm JSON skeleton
[ ] TASK-0001-011  FAPI 2.0 Client Policy
[ ] TASK-0001-012  Government client registered
[ ] TASK-0001-013  WebAuthn AAL3 flow
[ ] TASK-0001-014  Back/front-channel logout
[ ] TASK-0001-015  CI pipeline applies config

PHASE 2 — Scaffold
[ ] TASK-0001-020  Solution structure
[ ] TASK-0001-021  NuGet + lock file
[ ] TASK-0001-022  Config + vault integration

PHASE 3 — Middleware (all require Security Reviewer PR)
[ ] TASK-0001-030  SecurityHeadersMiddleware
[ ] TASK-0001-031  DpopProofValidator (core logic)
[ ] TASK-0001-032  DpopValidationMiddleware
[ ] TASK-0001-033  JtiReplayCache
[ ] TASK-0001-034  Replay check in JWT events
[ ] TASK-0001-035  AcrRequirement + Handler
[ ] TASK-0001-036  JWT Bearer configuration
[ ] TASK-0001-037  Authorization policies
[ ] TASK-0001-038  Rate limiting

PHASE 4 — Controllers
[ ] TASK-0001-040  ProfileController
[ ] TASK-0001-041  ProblemDetails factory

PHASE 5 — Observability
[ ] TASK-0001-050  AuthTelemetry
[ ] TASK-0001-051  SecurityEventEmitter
[ ] TASK-0001-052  OTel pipeline

PHASE 6 — Unit Tests
[ ] TASK-0001-060  DpopProofValidator tests (12/12)
[ ] TASK-0001-061  JtiReplayCache tests (5/5)
[ ] TASK-0001-062  AcrHandler tests (5/5)
[ ] TASK-0001-063  SecurityHeaders tests

PHASE 7 — Integration Tests
[ ] TASK-0001-070  Test fixtures (Testcontainers)
[ ] TASK-0001-071  Security scenarios (14/14)
[ ] TASK-0001-072  Full auth flow test

PHASE 8 — Docs
[ ] TASK-0001-080  OpenAPI 3.1 spec
[ ] TASK-0001-081  Operational runbook
[ ] TASK-0001-082  Spec/Plan status updated

CI GATES (all 9 green)
[ ] Gate 1  SAST — zero HIGH/CRITICAL
[ ] Gate 2  Dependency scan — zero CRITICAL CVEs  
[ ] Gate 3  Secrets scan — clean
[ ] Gate 4  Coverage — ≥ 90% security paths
[ ] Gate 5  DAST — zero HIGH
[ ] Gate 6  IaC scan — zero HIGH
[ ] Gate 7  Container scan — zero HIGH/CRITICAL
[ ] Gate 8  SBOM generated + signed
[ ] Gate 9  Image signatures verified
```
