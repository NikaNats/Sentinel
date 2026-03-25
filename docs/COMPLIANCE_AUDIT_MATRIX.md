# Compliance And Audit Matrix

**Last Updated:** 2026-03-25
**Status:** RFC-Compliant Minimal API Architecture with Full Zero-Reflection Support

## Scope

This matrix maps the current Sentinel codebase to the major standards and control themes it implements. All endpoints are implemented as Native AOT-compatible Minimal APIs (zero reflection).

## RFC Compliance Coverage

| RFC | Title | Sentinel Implementation | Status | Evidence |
|---|---|---|---|---|
| 6750 | OAuth 2.0 Bearer Token | `Authorization: Bearer $TOKEN` header | ✅ | Middleware validation in all endpoints |
| 7231 | HTTP Semantics | `Location` header on 201 responses | ✅ | DocumentEndpoints, FinanceEndpoints handlers |
| 7807 | Problem Details for HTTP APIs | ErrorCodes.cs with type URIs | ✅ | `/errors/*` error type constants |
| 8693 | OAuth 2.0 Token Exchange | `POST /auth/token-exchange` endpoint | ✅ | TokenExchangeEndpoints.cs (v1.1) |
| 8936 | Shared Signals and Events | `POST /ssf/events` receiver | ✅ | SsfEndpoints.cs, RFC 8936 async processing (202 Accepted) |
| 9110 | Idempotent HTTP Requests | `Idempotency-Key` deduplication (Redis) | ✅ | IdempotencyFilter, DocumentEndpoints, FinanceEndpoints |
| 9396 | Rich Authorization Requests | `authorization_details` claim validation | ✅ | SurgicalAuthorizationFilter, precision-safe amount comparison |
| 9413 | OpenID Connect Backchannel Logout | `POST /auth/backchannel-logout` endpoint | ✅ | BackchannelLogoutEndpoints.cs, silent error handling |
| 9449 | DPoP (Proof-of-Possession) | `DPoP` header with JWT proof + nonce | ✅ | All endpoints, nonce rotation, 401 challenge semantics |
| 9052 | CBOR Object Signing and Encryption | SD-JWT with selective disclosure | ✅ | SdJwt validator, disclosure digest validation |
| NIST 800-63B | Authentication & Lifecycle | ACR step-up, multi-factor enforcement | ✅ | AcrStepUpAuthorizationFilter, acr3 requirement |

## Standards Coverage (Detailed)

| Area | Standard / Theme | Current Status | Notes |
|---|---|---|---|
| Access token validation | JWT / OIDC | Implemented | issuer, audience, lifetime, algorithm allow-lists |
| Sender constraint | RFC 9449 DPoP | Implemented | nonce challenge, proof validation, thumbprint binding |
| Replay protection | OAuth security best practice | Implemented | JWT and proof JTI caches, Redis-atomic state |
| Selective disclosure | RFC 9052 SD-JWT | Implemented | disclosure digest validation and key binding |
| Shared security signals | RFC 8936 SSF | Implemented | SET validation and session revocation processing |
| Rich authorization | RFC 9396 RAR | Implemented | payload-bound transaction enforcement on transfers |
| Idempotency | RFC 9110 | Implemented | Idempotency-Key deduplication, Redis locks |
| Session invalidation | OIDC / logout hygiene | Implemented | blacklist TTL aligned with Keycloak session settings |
| Shared-secret validation | Timing-safe comparison | Implemented | constant-time compare in SSF controller |
| Problem Details | RFC 7807 | Implemented | Structured error responses with type URIs |
| Backchannel Logout | RFC 9413 | Implemented | Silent error handling, never leaks validation details |
| Post-quantum transition | ML-DSA rollout groundwork | Partial | allow-list and thumbprint support present; full interoperability remains rollout-sensitive |

## Key Evidence

| Control | Evidence (Location in Codebase) |
|---|---|
| DPoP nonce challenge uses `401` | [ARCHITECTURE.md](ARCHITECTURE.md), Section: Request Pipeline |
| DPoP proof validation | `src/Sentinel.AspNetCore/Filters/DpopValidationMiddleware.cs` |
| Idempotency-Key deduplication | `src/Sentinel.AspNetCore/Filters/IdempotencyFilter.cs` |
| ACR Step-Up enforcement | `src/Sentinel.AspNetCore/Filters/AcrStepUpAuthorizationFilter.cs` |
| Rich Authorization validation | `samples/Sentinel.Sample.MinimalApi/Filters/SurgicalAuthorizationFilter.cs` |
| SD-JWT verifier | `src/Sentinel.Infrastructure/Auth/SdJwt/*` |
| SSF validator and processor | `src/Sentinel.AspNetCore/Endpoints/SsfEndpoints.cs` |
| Backchannel Logout | `src/Sentinel.AspNetCore/Endpoints/BackchannelLogoutEndpoints.cs` (RFC 9413 silent handling) |
| Shared OIDC configuration manager is singleton | `src/Sentinel.Infrastructure/DependencyInjection/*` |
| Timing-safe token comparison | SSF endpoints use `CryptographicOperations.FixedTimeEquals()` |
| Finance payload-bound authorization | `samples/Sentinel.Sample.MinimalApi/Filters/SurgicalAuthorizationFilter.cs` |
| Modular tests (141 passing) | `tests/Sentinel.Tests.Unit/` with zero MVC dependencies |
| Problem Details responses | `src/Sentinel.AspNetCore/Errors/ErrorCodes.cs` |
| Native AOT support | `samples/Sentinel.Sample.MinimalApi/Sentinel.Sample.MinimalApi.csproj` with `<PublishAot>true</PublishAot>` |
| Zero-reflection endpoints | All handlers in `src/Sentinel.AspNetCore/Endpoints/*.cs` are static methods with compiled signatures |

## Audit Notes

Best practice for audit readiness in this repo:

1. **Use code evidence plus docs** - Don't rely on documentation alone; examine actual Minimal API handlers in `src/Sentinel.AspNetCore/Endpoints/*.cs`
2. **Verify RFC compliance** - Check endpoint signatures, filter chains, and error response structures
3. **Run test suite** - Execute `dotnet test tests/Sentinel.Tests.Unit -c Release` (141/141 tests must pass)
4. **Validate AOT support** - Build sample: `dotnet build samples/Sentinel.Sample.MinimalApi -c Release` (should have 0 warnings)
5. **Check zero-reflection** - All endpoints are static methods; no MVC model binding reflection

## Migration Status (v1.0 → v1.1)

| Component | Status | Details |
|---|---|---|
| Core Endpoints | ✅ Minimal APIs | `src/Sentinel.AspNetCore/Endpoints/*.cs` |
| Filters | ✅ IEndpointFilter | Idempotency, ACR Step-Up, RAR validation |
| Test Coverage | ✅ 141/141 passing | Zero MVC dependencies, RFC compliance verified |
| Sample App | ✅ AOT-ready | `samples/Sentinel.Sample.MinimalApi` with `PublishAot=true` |
| Zero Reflection | ✅ 100% | All MVC removed, InMemory fallback eliminated (Fail-Closed only) |
| Native AOT | ✅ Production Ready | Self-contained binaries; no reflection metadata |

## Next Audit Cycle (v2.0 - 2026-Q3)

- [x] Remove `Sentinel.Presentation` MVC controllers *(COMPLETED)*
- [x] Archive historical gate/packaging documents *(COMPLETED)*
- [x] Eliminate InMemory fallback logic (Fail-Closed semantics only) *(COMPLETED)*
- [x] Remove deprecated abstraction bridges *(COMPLETED)*
- [ ] Publish AOT-only distribution package
- [ ] Update container images to use self-contained binaries
- [ ] Re-certify RFC compliance with production deployment
