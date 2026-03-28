# Compliance And Audit Matrix

Last Updated: 2026-03-29
Scope: Sentinel core modules, ASP.NET integration layer, and reference sample

## 1. Method

This matrix maps standards and control objectives to implementation evidence in the repository.

Legend:

- Implemented: control exists in current code paths
- Partial: foundational pieces exist, full end-to-end readiness still pending
- Gap: no verified implementation in current baseline

## 2. Standards Mapping

| Standard | Control Theme | Status | Primary Evidence |
|---|---|---|---|
| RFC 6750 | Bearer token usage at API boundary | Implemented | src/Sentinel.AspNetCore/Endpoints/AuthEndpoints.cs |
| RFC 7807 | Problem details error shape | Implemented | src/Sentinel.AspNetCore/Errors/ErrorCodes.cs and endpoint returns |
| RFC 8693 | Token exchange endpoint | Implemented | src/Sentinel.AspNetCore/Endpoints/TokenExchangeEndpoints.cs |
| RFC 8936 | SSF/SET event ingestion | Implemented | src/Sentinel.AspNetCore/Endpoints/SsfEndpoints.cs, src/Sentinel.SSF |
| RFC 9110 | Idempotency semantics for state change | Implemented | src/Sentinel.AspNetCore/Filters/IdempotencyFilter.cs |
| RFC 9396 | Rich authorization details evaluation | Implemented | src/Sentinel.Rar, samples/Sentinel.Sample.MinimalApi/Filters/SurgicalAuthorizationFilter.cs |
| RFC 9413 | Backchannel logout endpoint behavior | Implemented | src/Sentinel.AspNetCore/Endpoints/BackchannelLogoutEndpoints.cs |
| RFC 9449 | DPoP validation and nonce challenge | Implemented | src/Sentinel.DPoP, src/Sentinel.AspNetCore/Middleware/DpopValidationMiddleware.cs |
| NIST SP 800-63B | ACR step-up pattern | Implemented | src/Sentinel.AspNetCore/Filters/AcrStepUpAuthorizationFilter.cs |

## 3. Control Objective Coverage

| Objective | Status | Notes |
|---|---|---|
| Sender-constrained token use | Implemented | DPoP proof and cnf/jkt binding validation paths exist |
| Replay resistance | Implemented | JTI replay checks for tokens/proofs and fail-closed behavior |
| Session invalidation | Implemented | Session blacklist and SSF-triggered revocation paths |
| Event-driven risk response | Implemented | SSF event intake and processing modules |
| Payload-bound high-risk authorization | Implemented | RAR-aware transfer guard filter in sample |
| Operational observability for security events | Implemented | Sentinel.Security.Diagnostics central telemetry primitives |
| Timing-safe shared secret checks | Implemented | SSF auth token fixed-time comparison |
| Production container hardening | Partial | compose exists, active Dockerfile packaging path missing |

## 4. Evidence Index

### 4.1 Endpoint Layer

- src/Sentinel.AspNetCore/Endpoints/SentinelEndpointExtensions.cs
- src/Sentinel.AspNetCore/Endpoints/AuthEndpoints.cs
- src/Sentinel.AspNetCore/Endpoints/TokenExchangeEndpoints.cs
- src/Sentinel.AspNetCore/Endpoints/SsfEndpoints.cs
- src/Sentinel.AspNetCore/Endpoints/BackchannelLogoutEndpoints.cs

### 4.2 Protocol and Security Modules

- src/Sentinel.DPoP
- src/Sentinel.Session
- src/Sentinel.SSF
- src/Sentinel.SdJwt
- src/Sentinel.Rar

### 4.3 Adapter and State Modules

- src/Sentinel.Redis
- src/Sentinel.Keycloak
- src/Sentinel.Infrastructure

### 4.4 Diagnostics

- src/Sentinel.Security.Diagnostics/AuthTelemetry.cs
- src/Sentinel.Security.Diagnostics/SecurityEventEmitter.cs
- src/Sentinel.Security.Diagnostics/SecurityContextHasher.cs

### 4.5 Sample Demonstrations

- samples/Sentinel.Sample.MinimalApi/Program.cs
- samples/Sentinel.Sample.MinimalApi/Endpoints/FinanceEndpoints.cs
- samples/Sentinel.Sample.MinimalApi/Filters/SurgicalAuthorizationFilter.cs

## 5. Audit Procedure (Recommended)

1. Build verification
	- dotnet build Sentinel.slnx -v minimal
2. Security behavior verification
	- dotnet test tests/Sentinel.Tests.Security -v minimal
3. Core regression verification
	- dotnet test tests/Sentinel.Tests.Unit -v minimal
4. Contract review
	- docs/OPENAPI_3_1.yaml against endpoint mapping in src/Sentinel.AspNetCore/Endpoints
5. Operational readiness review
	- docs/CONTAINER_BUILD_READINESS.md and docker-compose.yml consistency

## 6. Known Gaps and Exceptions

1. Container release packaging is incomplete in-repo (missing active Dockerfile target referenced by compose).
2. OpenAPI contract is manually maintained and must be updated per endpoint change.
3. Some controls are demonstrated in the sample host rather than enforced in all possible consumer hosts by default.

## 7. Next Compliance Actions

1. Add and validate a production-grade Dockerfile aligned to net10 runtime.
2. Automate OpenAPI drift detection in CI against endpoint mappings.
3. Add explicit release checklist sign-off for DPoP, SSF, RAR, and session-revocation behavior.
