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
- Operational runbook: [Auth Token Issuance Runbook](./docs/runbooks/auth-token-issuance.md)

## Implementation Status

| Area | Status | Notes |
|---|---|---|
| API host and middleware pipeline | Implemented | Security middleware chain and centralized exception handling are active |
| JWT validation and policy authorization | Implemented | Issuer, audience, lifetime, algorithms, ACR and scope enforcement |
| DPoP proof validation | Implemented | htm, htu, iat window, typ, alg, jwk, cnf.jkt checks |
| Replay protection | Implemented | Redis-backed jti cache, fail-closed behavior on cache outage |
| mTLS token binding | Implemented | cnf.x5t#S256 compared with presented client certificate hash |
| OpenTelemetry and metrics endpoint | Implemented | Tracing, metrics counters/histograms, Prometheus scrape endpoint |
| Integration and unit testing | Implemented | 48 tests passing in current main branch state |
| Full OAuth PAR and PKCE orchestration endpoint set | Planned/Externalized | Keycloak-driven flow orchestration remains infrastructure and client-driven |

## Architecture Overview

### Runtime Pipeline

The API pipeline applies controls in a defense-in-depth sequence:

1. Global exception handler and problem details formatting
2. Security response header hardening
3. Global fixed-window rate limiter
4. DPoP validation middleware
5. Replay cache failure middleware (fail-closed guard)
6. HTTPS redirection and routing
7. JWT authentication
8. mTLS certificate binding middleware
9. ACR presence validation middleware
10. Authorization policy enforcement
11. Controller endpoint execution and Prometheus scrape endpoint

### Core Security Components

- DPoP validator validates proof structure, algorithm, type, signature, claims, key thumbprint, and replay state
- Replay cache stores and checks jti keys with explicit TTL to block token or proof reuse
- Security event emitter produces structured warning/critical events with correlation IDs
- ACR and scope authorization handlers apply fine-grained policy checks at endpoint authorization time

## Repository Layout

```text
Sentinel/
|- Sentinel.sln
|- docker-compose.yml
|- Makefile
|- docs/
|  |- runbooks/
|     |- auth-token-issuance.md
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

## Quick Start

### 1. Restore, Build, Test

```powershell
dotnet restore Sentinel.sln --locked-mode
dotnet build Sentinel.sln -c Release
dotnet test Sentinel.sln
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

Implemented hardening controls include:

- JWT validation:
    - issuer and audience required
    - lifetime required with zero clock skew
    - signed tokens required
    - algorithm allow-list limited to PS256 and ES256
- DPoP validation:
    - token and proof format checks
    - typ must be dpop+jwt
    - proof alg restricted to PS256 or ES256
    - embedded jwk required and private jwk material rejected
    - signature validated against embedded jwk
    - htm and htu binding enforced
    - iat freshness window enforced
    - access token cnf.jkt must match proof jwk thumbprint
    - proof jti replay blocked with Redis
    - DPoP-Nonce response header generated on valid proof
- Access token replay defense:
    - jti claim required and cached until token exp
    - duplicate jti rejected and emitted as critical security event
    - Redis outage triggers fail-closed behavior and 503 for protected paths
- mTLS sender-constraining:
    - cnf.x5t#S256 is validated against the presented client certificate SHA-256 hash
- HTTP response hardening:
    - HSTS, CSP, no-sniff, frame deny, referrer policy, cache-control no-store, and permissions policy
    - Server and X-Powered-By headers removed
- Request abuse control:
    - fixed-window global limiter: 100 requests/minute with queue size 2

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
- Replay cache error semantics and TTL storage
- mTLS binding checks with cert/no-cert branches
- ACR authorization ranking behavior
- Security response header enforcement

### Integration Tests

Focus areas:
- End-to-end protected endpoint access with valid DPoP proof
- Expired token rejection
- Invalid audience rejection
- Missing required scope rejection
- DPoP key mismatch attack scenario rejection
- Replay detection across repeated proofs
- Rate limiter behavior under burst traffic

Current baseline:
- 20 tests passing on main branch in the latest local validation run

## Containerization And Runtime Hardening

- Multi-stage Docker build with locked restore and release publish
- Runtime image runs as non-root user 1654
- DOTNET_EnableDiagnostics disabled in container runtime
- Kestrel configured for TLS 1.3 and delayed client certificate mode
- FIPS compatibility switch enabled; Linux FIPS kernel flag is detected and logged

## Development Workflow

This project follows a spec-driven workflow:

1. Define or refine security behavior in SPEC-0001
2. Plan implementation scope in PLAN-0001
3. Track execution in TASK-0001
4. Implement code and tests together
5. Validate with unit/integration tests and security scan
6. Update runbook and project documentation

## Contributing Standards

All changes should:

1. Align with the specification and threat model
2. Preserve or improve fail-closed security posture
3. Include tests for both happy path and abuse-path behavior
4. Maintain structured logging and telemetry semantics
5. Update documentation and runbooks when behavior changes

## Known Considerations

- The solution currently targets .NET 11 preview packages, which may introduce breaking changes before GA.
- HTTPS metadata validation is disabled in local development configuration and must be enforced in production.
- Some OAuth orchestration steps (for example PAR and PKCE client choreography) are primarily handled by Keycloak and external clients rather than API endpoints in this service.

## License

Proprietary. See LICENSE for usage terms.
