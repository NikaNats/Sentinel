# Sentinel

Sentinel is a security-focused ASP.NET Core Web API that enforces sender-constrained token validation patterns aligned with FAPI 2.0 Baseline and Advanced hardening goals.

The current implementation provides:
- DPoP access token handling with proof validation and nonce issuance
- Redis-backed replay detection for both access token jti and DPoP proof jti
- ACR and scope-based authorization requirements
- mTLS certificate binding checks for cnf.x5t#S256-bound tokens
- Strict JWT algorithm constraints and zero clock skew lifetime validation
- Security telemetry, security headers, rate limiting, and structured error handling

## Specifications And Delivery Artifacts

- Specification: [SPEC-0001 - User Authentication and Token Issuance](./.specify/specs/SPEC-0001-auth-token-issuance.md)
- Implementation plan: [PLAN-0001 - Auth Implementation](./.specify/plans/PLAN-0001-auth-implementation.md)
- Task breakdown: [TASK-0001 - Auth Implementation Tasks](./.specify/tasks/TASK-0001-auth-implementation.md)

## Comprehensive Documentation Suite

**Production-grade documentation for all audiences.** Start with the [Documentation Index](./docs/README.md).

| Document | Audience | Purpose |
|----------|----------|---------|
| [ARCHITECTURE.md](./docs/ARCHITECTURE.md) | Architects, Engineers | 10 Architecture Decision Records (ADRs) explaining DPoP, replay cache, rate limiting, nonce management, middleware ordering, idempotency, and operational design |
| [SDK_LESS_INTEGRATION_GUIDE.md](./docs/SDK_LESS_INTEGRATION_GUIDE.md) | Client Developers | Complete HTTP/REST integration guide with DPoP proof generation in 5 languages (JS, Python, Java, C#, Go) and full end-to-end examples |
| [LIVING_THREAT_MODEL.md](./docs/LIVING_THREAT_MODEL.md) | Security Teams, Auditors | 21 identified threats across 7 categories with mitigation analysis, likelihood × impact matrix, and residual risk assessment |
| [SRE_SOC_RUNBOOKS.md](./docs/SRE_SOC_RUNBOOKS.md) | SRE, SOC, On-Call | Monitoring, alerting, incident response procedures, troubleshooting guides, and maintenance checklists with bash/PowerShell commands |
| [COMPLIANCE_AUDIT_MATRIX.md](./docs/COMPLIANCE_AUDIT_MATRIX.md) | Compliance, Auditors | Compliance framework mapping (OAuth 2.0, JWT, DPoP RFC 9449, FAPI 2.0 Baseline) with 40+ audit checklist items |
| [OPENAPI_3_1.yaml](./docs/OPENAPI_3_1.yaml) | API Consumers | Formal OpenAPI 3.1 specification; machine-readable API contract for SDK generation and API gateway integration |
| [BUILD_CONFIGURATION_GUIDE.md](./docs/BUILD_CONFIGURATION_GUIDE.md) | Developers, DevOps | Directory.Build.props explanation, build workflow, code analysis policy, AOT/reproducibility, and troubleshooting |

**Quick Start by Role:**
- **Client Developer:** Start with [SDK_LESS_INTEGRATION_GUIDE.md](./docs/SDK_LESS_INTEGRATION_GUIDE.md) and [OPENAPI_3_1.yaml](./docs/OPENAPI_3_1.yaml)
- **SRE / Operations:** Start with [SRE_SOC_RUNBOOKS.md](./docs/SRE_SOC_RUNBOOKS.md)
- **Security / Compliance:** Start with [LIVING_THREAT_MODEL.md](./docs/LIVING_THREAT_MODEL.md) and [COMPLIANCE_AUDIT_MATRIX.md](./docs/COMPLIANCE_AUDIT_MATRIX.md)
- **Architect / Lead Engineer:** Start with [ARCHITECTURE.md](./docs/ARCHITECTURE.md)
- **Developer / DevOps:** Start with [BUILD_CONFIGURATION_GUIDE.md](./docs/BUILD_CONFIGURATION_GUIDE.md)

## Implementation Status

| Area | Status | Notes |
|---|---|---|
| API host and middleware pipeline | Implemented | Security middleware chain and centralized exception handling are active |
| JWT validation and policy authorization | Implemented | Issuer, audience, lifetime, algorithms, ACR and scope enforcement |
| DPoP proof validation | Implemented | htm, htu, iat window, typ, alg, jwk, cnf.jkt checks; RFC 9449 compliant nonce challenge-response |
| Replay protection | Implemented | Atomic Redis-backed jti cache (SET NX), fail-closed behavior, 60s TTL alignment with token lifetime |
| DPoP nonce management | Implemented | Per-JWK-thumbprint rotating nonce; atomic compare-delete consumption; 60s TTL |
| mTLS token binding | Implemented | cnf.x5t#S256 compared with presented client certificate hash; optional second factor |
| Rate limiting | Implemented | Dual-partition chained limiter (per-identity + per-IP); per-anonymous-IP isolation |
| Idempotency enforcement | Implemented | Logout idempotency with state machine (IN_PROGRESS→409, COMPLETED→204) |
| Session management | Implemented | Refresh token rotation; session blacklist on logout; TTL aligned with Keycloak (8h default) |
| OpenTelemetry and metrics endpoint | Implemented | Tracing, metrics counters/histograms, Prometheus scrape endpoint; security event telemetry |
| Integration and unit testing | Implemented | 50/50 tests passing with full security scenario coverage |
| Full OAuth PAR and PKCE orchestration endpoint set | Planned/Externalized | Keycloak-driven flow orchestration remains infrastructure and client-driven |

## Architecture Overview

### Runtime Pipeline

The API pipeline applies controls in a defense-in-depth sequence:

1. Global exception handler and problem details formatting
2. Security response header hardening (HSTS, CSP, frame-deny, no-sniff, cache-control)
3. Global fixed-window rate limiter (per-identity + per-IP dual partition)
4. JWT authentication (issuer, audience, lifetime, algorithm validation)
5. Rate limiter evaluation (both partitions must have available quota)
6. DPoP validation middleware (proof structure, signature, htm/htu binding, nonce validation)
7. mTLS certificate binding middleware (optional cnf.x5t#S256 validation)
8. ACR presence validation middleware
9. Authorization policy enforcement (scope, ACR requirements per endpoint)
10. Controller endpoint execution
11. Response headers (DPoP-Nonce for next request rotation)
12. Prometheus scrape endpoint (/metrics)

### Core Security Components

- **DPoP validator** enforces RFC 9449 compliance: validates proof signature, type, algorithm, htm/htu binding, iat freshness (±60s), jti proof replay via atomic Redis cache, and per-thumbprint nonce consumption
- **Replay cache** stores JWT jti and proof jti with atomic SET NX (When.NotExists) semantics; fail-closed returns 503 on Redis unavailability
- **Nonce store** manages per-JWK-thumbprint rotating nonces; atomic compare-delete transaction prevents consumption race; challenges issue fresh nonce on stale/consumed mismatches
- **Rate limiter** implements dual-partition chained enforcement: identity partition (sub+client_id or per-IP if anonymous) and always-present IP partition; 429 response includes Retry-After header
- **Security event emitter** produces structured OpenTelemetry Activity events with correlation IDs for SIEM pivoting
- **ACR and scope authorization handlers** apply fine-grained policy checks at endpoint level using claims validation

## Repository Layout

```text
Sentinel/
|- Sentinel.slnx
|- Directory.Build.props               ← Centralized build config (all projects inherit)
|- docker-compose.yml
|- Makefile
|- docs/
|  |- README.md                         ← Documentation index
|  |- ARCHITECTURE.md                   ← ADRs (10 decisions)
|  |- SDK_LESS_INTEGRATION_GUIDE.md     ← Client integration (5 languages)
|  |- LIVING_THREAT_MODEL.md            ← Security threat analysis (21 threats)
|  |- SRE_SOC_RUNBOOKS.md               ← Operational procedures
|  |- COMPLIANCE_AUDIT_MATRIX.md        ← Regulatory framework mapping
|  |- OPENAPI_3_1.yaml                  ← API specification (OpenAPI)
|  |- BUILD_CONFIGURATION_GUIDE.md      ← Build config explanation & workflow
|- artifacts/                           ← Centralized build output (bin/obj)
|  |- bin/
|  |- obj/
|- infra/
|  |- keycloak/
|     |- realms/
|        |- sentinel.json
|- .github/
|  |- workflows/
|  |- agents/
|  |- prompts/
|- .specify/
|  |- specs/
|  |- plans/
|  |- tasks/
|- src/
|  |- Sentinel.Domain/
|  |- Sentinel.Application/
|  |- Sentinel.Infrastructure/
|  |- Sentinel.Presentation/
|- tests/
|  |- Sentinel.Tests/
|     |- Integration/
|     |- Unit/
|- artifacts/                          ← Build output (bin/obj centralized)
```

## Technology Stack

| Component | Version | Usage |
|---|---|---|
| .NET SDK | 11.0 preview | Build and runtime |
| ASP.NET Core | 11.0 preview packages | API framework and middleware |
| Keycloak | 26.1 image in compose | Authorization server and realm management |
| Redis | 7.4 alpine | Replay cache backing store |
| OpenTelemetry | 1.13 to 1.14 packages | Tracing, metrics, exporter integration |
| xUnit + Testcontainers | Current project references | Unit and integration validation |

## Prerequisites

- Windows, Linux, or macOS development environment
- .NET 11 SDK preview installed
- Docker Desktop or Docker Engine
- Optional: Trivy for image vulnerability scanning

## Build Configuration

**Directory.Build.props** provides centralized configuration for all projects:

| Feature | Setting | Purpose |
|---------|---------|---------|
| **Artifacts Layout** | `UseArtifactsOutput: true` | Centralized bin/obj → artifacts/ folder (no tree pollution) |
| **Framework** | `TargetFramework: net11.0` | .NET 11 preview (latest) |
| **Code Analysis** | `AnalysisLevel: latest-all` | Aggressive code quality checks (catch issues early) |
| **Warnings as Errors** | Release/CI only | Zero-warning policy; enforced at CI stage |
| **AOT Compatibility** | Enabled for executables | Native AOT readiness; trim-safe code analysis |
| **Security** | NuGetAudit, ControlFlowGuard | Block vulnerable packages; enable Control Flow Guard |
| **Reproducible Builds** | `Deterministic: true` | Dev machine binary = CI binary (no variance) |
| **Language** | `Nullable: enable`, `ImplicitUsings: enable` | Modern C# with strict null safety |
| **Lock Files** | `RestorePackagesWithLockFile: true` | Frozen transitive dependencies for reproducibility |

All projects inherit these settings automatically; overrides in individual .csproj only when necessary.

## Quick Start

### 1. Restore, Build, Test

```powershell
dotnet restore Sentinel.slnx --locked-mode
dotnet build Sentinel.slnx -c Release
dotnet test Sentinel.slnx
```

### 2. Start Local Infrastructure And API With Docker Compose

```powershell
docker-compose up --build -d
```

Services:
- Keycloak: https://localhost:8443 and http://localhost:8080
- Redis: localhost:6379
- Sentinel API: http://localhost:5260

### 3. Run API Directly (Without Compose)

```powershell
cd src/Sentinel.Presentation
dotnet run
```

### 4. Stop Local Stack

```powershell
docker-compose down -v
```

## Make Targets

```text
make build      # locked restore + release build
make test       # run all tests
make lint       # dotnet format verification
make sec-scan   # build image + trivy scan (critical/high)
make up         # docker-compose up --build -d
make down       # docker-compose down -v
make all        # build + lint + test + sec-scan
```

## Configuration Reference

Minimum required keys:

| Key | Purpose | Example |
|---|---|---|
| ConnectionStrings:Redis | Replay cache backend | localhost:6379 |
| Keycloak:Authority | Token issuer authority | https://localhost:8443/realms/sentinel |
| Keycloak:Audience | Expected access token audience | sentinel-api |
| Keycloak:RequireHttpsMetadata | Dev metadata over HTTP toggle | false (development only) |
| FeatureFlags:Auth:DpopFlow | Feature toggle placeholder | true |

Notes:
- Production deployments should keep HTTPS metadata required.
- Redis availability is part of the security boundary; service degrades fail-closed for replay-protected flows when unavailable.

## API Surface

### Protected Endpoint

- GET /v1/Profile

Requirements:
- Authenticated JWT passed in Authorization header with DPoP scheme
- Matching DPoP proof in DPoP header
- Policy ReadProfile satisfied:
    - scope includes profile
    - acr claim meets minimum acr2

Example response model:

```json
{
    "sub": "subject-id",
    "displayName": "display name",
    "roles": ["user"]
}
```

## Security Controls

Implemented RFC 9449 (DPoP) + FAPI 2.0 Baseline hardening controls:

**JWT Validation:**
- Issuer and audience required; validated against Keycloak realm configuration
- Lifetime required with zero clock skew tolerance
- Signed tokens required; algorithm allow-list restricted to ES256, RS256, PS256
- JTI (JWT ID) replay detection: stored in Redis cache with TTL matching token lifetime (60s)
- Duplicate JTI rejection: return 503 Service Unavailable (fail-closed)

**DPoP Proof Validation (RFC 9449):**
- Token and proof format validation
- Type must be `dpop+jwt`; algorithm restricted to ES256, RS256, PS256
- Embedded public JWK required; private key material rejected
- Signature validated against embedded JWK
- `htm` (HTTP method) and `htu` (HTTP URI) binding enforced and compared to request
- `iat` freshness window enforced (±60 seconds clock skew tolerance)
- Access token `cnf.jkt` must match proof JWK thumbprint (S256)
- Proof JTI replay blocked with atomic Redis SET NX (When.NotExists) cache
- Per-JWK-thumbprint nonce required in proof claims
- Atomic nonce consumption via Redis transaction compare-delete (prevents reuse)

**Nonce Challenge-Response (RFC 9449 §4.3):**
- Server-issued nonce included in `DPoP-Nonce` response header
- Nonce tied to client's JWK thumbprint; per-identity nonce sequence
- Nonce lifetime: 60 seconds; expiration triggers challenge re-issuance
- Initial unauthenticated request returns 400 Bad Request + nonce challenge
- Client includes nonce in next proof; server validates before consumption
- Stale/consumed nonce triggers new challenge issuance with fresh nonce
- Client must update cached nonce from every response header

**Access Token Replay Defense:**
- JTI claim required and enforced
- Duplicate JTI within token lifetime (60s) rejected
- Redis outage triggers fail-closed behavior (503 Service Unavailable)

**mTLS Sender-Constraining (Optional):**
- `cnf.x5t#S256` validated against presented client certificate SHA-256 hash
- Enables optional second-factor binding (mTLS + DPoP)

**Rate Limiting:**
- Dual-partition chained enforcement:
  - **Identity partition:** `{sub}:{client_id}` if authenticated; `{remote_ip}` if anonymous
  - **IP partition:** Always `{remote_ip}` (layered defense)
- Both partitions must have available quota; if either exhausted → 429 Too Many Requests
- Per-identity quota: 10-20 req/min (configurable; auth endpoints lower)
- Per-IP quota: 100 req/min (configurable; anonymous isolation)
- Gradeful degradation: 429 response includes `Retry-After` header

**Session Management:**
- Refresh token rotation enforced on every refresh
- Refresh token reuse detected; second use triggers session blacklist and forces re-authentication
- Session blacklist on logout with TTL aligned to Keycloak `SsoSessionMaxLifespanSeconds` (default 8 hours)
- Idempotency enforcement on logout: `Idempotency-Key` header required
- Idempotency state machine: IN_PROGRESS (409) vs COMPLETED (204) distinction
- Backchannel logout support (Keycloak-initiated session termination)

**HTTP Response Hardening:**
- HSTS (HTTP Strict-Transport-Security): 1 year max-age
- CSP (Content-Security-Policy): restrict inline scripts, external resources
- X-Content-Type-Options: nosniff (prevent MIME-type sniffing)
- X-Frame-Options: DENY (prevent clickjacking)
- X-XSS-Protection: 1; mode=block (browser XSS filter)
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy: restrict API capabilities
- Cache-Control: no-store, must-revalidate (prevent caching of sensitive responses)
- Server and X-Powered-By headers removed

**OpenTelemetry Security Telemetry:**
- Security events emitted as Activity events with structured attributes
- Events: `security:authentication_success`, `security:invalid_dpop_proof`, `security:use_dpop_nonce`, `security:token_reuse_detected`, `security:rate_limit_exceeded`, `security:session_revoked`
- W3C Trace Context for correlation across distributed components
- Sensitive data excluded from attributes (PII masking)

## Observability

### Tracing

- Activity source: Sentinel.Auth.Tracing
- Includes DPoP validation and replay cache operations

### Metrics

- Meter: Sentinel.Auth.Metrics
- Counters:
    - auth.dpop.failures
    - auth.jti.replays_total
    - auth.token.issued
- Histogram:
    - auth.token.validation.duration_ms

### Operational Signals

- Security events include correlation IDs for SIEM pivoting
- Replay and auth failure events map to runbook actions in docs/runbooks/auth-token-issuance.md

## Testing Strategy

### Unit Tests

Focus areas:
- DPoP validator acceptance and replay rejection
- DPoP nonce store read-without-delete, atomic storage with clobber-safety, atomic consume-if-matches
- JTI replay cache atomic SET NX (When.NotExists) semantics and TTL handling
- Refresh token rotation and reuse detection
- mTLS binding checks with cert/no-cert branches
- ACR authorization ranking behavior
- Idempotency state machine (IN_PROGRESS vs COMPLETED branches)
- Security response header enforcement

### Integration Tests

Focus areas:
- End-to-end FAPI2-compliant authenticated flow with DPoP proof per request
- DPoP nonce challenge flow: unauthenticated 400 → nonce in header → prove with nonce → success
- Token replay detection (JTI already used within 60s window)
- DPoP proof replay detection (proof JTI + nonce reuse)
- Refresh token rotation and reuse detection (family tree)
- Expired token rejection
- Invalid audience rejection
- Missing required scope rejection
- Insufficient ACR rejection
- Rate limiter behavior: per-identity saturation, per-IP saturation, anonymous per-IP isolation
- DPoP key mismatch attack scenario rejection
- Real Keycloak integration (non-DPoP binding tests)

**Current Test Status:**
- **50/50 tests passing** (100% pass rate)
- Integration test suites: AuthFlow (2), SecurityScenarios (6), RealKeycloak (2)
- Unit test suites: JtiReplayCache (2), DpopProofValidator (3), Idempotency (3), Auth (4), Backchannel (2), Services (2)
- All security scenario paths exercised (DPoP nonce, token replay, proof replay, rate limits, ACR, scope validation)

## Containerization And Runtime Hardening

- Multi-stage Docker build with locked restore and release publish
- Runtime image runs as non-root user 1654
- DOTNET_EnableDiagnostics disabled in container runtime
- Kestrel configured for TLS 1.3 and delayed client certificate mode
- FIPS compatibility switch enabled; Linux FIPS kernel flag is detected and logged

## Development Workflow

This project follows a spec-driven workflow with comprehensive documentation:

1. Define or refine security behavior in SPEC-0001 and living threat model ([LIVING_THREAT_MODEL.md](./docs/LIVING_THREAT_MODEL.md))
2. Plan implementation scope in PLAN-0001
3. Track execution in TASK-0001
4. Implement code and tests together (unit + integration)
5. Validate with full test suite (target: 50/50+ tests passing)
6. Security scan for vulnerabilities (Trivy)
7. Update architecture documentation ([ARCHITECTURE.md](./docs/ARCHITECTURE.md)) when decisions change
8. Update operational runbooks ([SRE_SOC_RUNBOOKS.md](./docs/SRE_SOC_RUNBOOKS.md)) when behavior changes
9. Update compliance matrix ([COMPLIANCE_AUDIT_MATRIX.md](./docs/COMPLIANCE_AUDIT_MATRIX.md)) if standards impact
10. Update API specification if endpoints/schemas change ([OPENAPI_3_1.yaml](./docs/OPENAPI_3_1.yaml))

## Contributing Standards

All changes should:

1. Align with FAPI 2.0 Baseline and RFC 9449 (DPoP) specifications
2. Maintain or improve fail-closed security posture (e.g., 503 on cache unavailability, not bypass)
3. Include comprehensive tests for both happy path and abuse-path behavior
4. Maintain structured logging and OpenTelemetry telemetry semantics
5. Pass full test suite (unit + integration); target 100% pass rate
6. Pass security scan (Trivy; no critical/high vulnerabilities)
7. Update architecture decisions ([ARCHITECTURE.md](./docs/ARCHITECTURE.md)) if design rationale changes
8. Update threat model ([LIVING_THREAT_MODEL.md](./docs/LIVING_THREAT_MODEL.md)) if new threats identified
9. Update compliance matrix ([COMPLIANCE_AUDIT_MATRIX.md](./docs/COMPLIANCE_AUDIT_MATRIX.md)) if framework alignment changes
10. Update operational runbooks ([SRE_SOC_RUNBOOKS.md](./docs/SRE_SOC_RUNBOOKS.md)) if operational procedures change
11. Update API specification ([OPENAPI_3_1.yaml](./docs/OPENAPI_3_1.yaml)) if endpoints or schemas change
12. Update integration guide ([SDK_LESS_INTEGRATION_GUIDE.md](./docs/SDK_LESS_INTEGRATION_GUIDE.md)) if client-facing behavior changes

## Known Considerations

- The solution currently targets .NET 11 preview packages, which may introduce breaking changes before GA.
- HTTPS metadata validation is disabled in local development configuration and must be enforced in production.
- Some OAuth orchestration steps (e.g., PAR and PKCE client choreography) are primarily handled by Keycloak and external clients rather than API endpoints in this service.
- Redis is part of the security boundary; the service fails closed (returns 503) if Redis becomes unavailable, blocking all protected resource access until Redis recovers.
- DPoP nonce has 60-second lifetime; clients must handle nonce expiration gracefully by retrying with new nonce on 400 challenge responses.
- Refresh token rotation is enforced; clients cannot reuse rotated refresh tokens (second use triggers session blacklist and forces re-authentication).
- Rate limiting uses per-identity (authenticated) or per-IP (anonymous) partitions; multi-IP coordinated attacks require upstream CDN/WAF mitigation (see [SRE_SOC_RUNBOOKS.md](./docs/SRE_SOC_RUNBOOKS.md) for DDoS procedures).
- See [LIVING_THREAT_MODEL.md](./docs/LIVING_THREAT_MODEL.md) for complete threat assessment and [ARCHITECTURE.md](./docs/ARCHITECTURE.md) for design rationale behind all security decisions.

## License

Proprietary. See LICENSE for usage terms.
