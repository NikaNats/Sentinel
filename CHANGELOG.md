# Changelog

All notable changes to the `NikaNats.Sentinel.*` packages. Versions follow [SemVer](https://semver.org/);
the version is set in `version.json` (Nerdbank.GitVersioning) and must be bumped before each release.

## [1.0.0] - Unreleased

### Added
- `AddSentinelJwtBearer(authority, audience, configure)` and `SentinelJwtBearerEvents.Create()`: strict JwtBearer
  defaults (exact issuer/audience, zero clock skew, PS256/ES256, HTTPS metadata) plus DPoP-scheme token
  extraction, `TokenValidationService` checks, sanitized RFC 9457 401 responses and JWKS kid-miss telemetry.
- `AddSentinelHostBridges()`: library-provided adapters between the `Security.Abstractions` and `Application`
  ports, so hosts no longer hand-write them.
- `AddSentinelSsfTokenValidation(issuer, audience)`: JWKS-backed SET validator (exact issuer/audience, PS256/ES256,
  generic errors). Previously every host had to write its own.
- `Ssf` options are bound by `AddSentinelAspNetCore()` and validated at startup.
- NuGet package README and icon.

### Changed (behavior)
- **SSF receiver is opt-in:** `Ssf:Enabled` now defaults to `false` (was `true`). Set it explicitly, and set
  `RequireAuthToken`/`AuthToken`. Startup fails if auth is required but no token is configured.
- The SSF endpoint returns 404 when disabled even if the SSF processing services are not registered (was 500).
- Options classes use `set` instead of `init`, so the Native AOT configuration binder populates them.

### Security
- SSF receiver: non-object JSON, non-string `set` values and bodies over 64 KiB now return 400 instead of a 5xx
  or an unbounded read.
- SSF revocation fails closed: an identity-provider revocation reported as failed is no longer acknowledged (202).
- Change-password and delete-account no longer report success when revoking other sessions fails.
- `POST /auth/refresh` no longer returns 200 with an empty `access_token`.
- 401 challenges no longer echo token-validator exception text to clients.
- Idempotency: an endpoint exception releases the lock (also on client abort) instead of blocking retries with
  409 until the 5-minute TTL.
- TLS certificate hot reload works: the file watcher was never enabled. It now watches the certificate
  directory, including Kubernetes symlink swaps, with a thread-safe debounce.
- Raw JTIs, DPoP thumbprints, session IDs and subjects removed from Redis, EF Core, session and Keycloak logs.
