# Compliance And Audit Matrix

**Last Updated:** 2026-03-21

## Scope

This matrix maps the current Sentinel codebase to the major standards and control themes it implements.

## Standards Coverage

| Area | Standard / Theme | Current Status | Notes |
|---|---|---|---|
| Access token validation | JWT / OIDC | Implemented | issuer, audience, lifetime, algorithm allow-lists |
| Sender constraint | RFC 9449 DPoP | Implemented | nonce challenge, proof validation, thumbprint binding |
| Replay protection | OAuth security best practice | Implemented | JWT and proof JTI caches |
| Selective disclosure | RFC 9901 SD-JWT | Implemented | disclosure digest validation and key binding |
| Shared security signals | RFC 9493 SET / SSF-style ingestion | Implemented | SET validation and session revocation processing |
| Rich authorization | RFC 9396-aligned pattern | Implemented at application layer | payload-bound transaction enforcement on finance transfer |
| Session invalidation | OIDC / logout hygiene | Implemented | blacklist TTL aligned with Keycloak session settings |
| Shared-secret validation | Timing-safe comparison | Implemented | constant-time compare in SSF controller |
| Post-quantum transition | ML-DSA rollout groundwork | Partial | allow-list and thumbprint support present; full interoperability remains rollout-sensitive |

## Key Evidence

| Control | Evidence |
|---|---|
| DPoP nonce challenge uses `401` | [ARCHITECTURE.md](ARCHITECTURE.md) |
| SD-JWT verifier and handler exist | `src/Sentinel.Infrastructure/Auth/SdJwt/*` |
| SSF validator and processor exist | `src/Sentinel.Infrastructure/Auth/Ssf/*` |
| Shared OIDC configuration manager is singleton | `src/Sentinel.Infrastructure/DependencyInjection/SentinelModuleBuilderExtensions.cs` |
| Timing-safe SSF auth token compare | `src/Sentinel.Presentation/Controllers/SsfController.cs` |
| SET freshness without `exp` | `src/Sentinel.Infrastructure/Auth/Ssf/JwtSsfTokenValidator.cs` uses bounded `iat` validation with documented suppression |
| Finance payload-bound authorization exists | `src/Sentinel.Presentation/Middleware/Filters/RequireSurgicalAuthorizationAttribute.cs` |
| Modular tests exist | `tests/Sentinel.Tests.Unit`, `tests/Sentinel.Tests.Integration`, `tests/Sentinel.Tests.Security` |

## Audit Notes

Best practice for audit readiness in this repo:

1. Use docs plus code evidence, not docs alone.
2. Treat historical gate files as supporting evidence only.
3. Re-check container/runtime alignment before asserting release readiness.
4. Re-run the modular test suites before compliance sign-off.
