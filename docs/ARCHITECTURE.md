# Sentinel Architecture

**Last Updated:** 2026-03-25
**Status:** Native AOT-Compatible Minimal APIs (Zero Reflection)
**Breaking Change:** v1.1 Migrated from MVC Controllers to Minimal APIs (v1.0 supports both)

## Overview

Sentinel is a layered, zero-reflection security framework built around Keycloak-issued identity, sender-constrained access (DPoP), replay resistance, session invalidation, and payload-bound authorization.

Architecture layers:

- `Sentinel.Domain` - Entity definitions, value objects, domain logic
- `Sentinel.Application` - Use cases, orchestration, business rules
- `Sentinel.Infrastructure` - Redis, Keycloak, Cryptography, Telemetry
- `Sentinel.AspNetCore` - Minimal API endpoints, IEndpointFilter implementations, middleware
- `Sentinel.Presentation` - **[DEPRECATED in v2.0]** Legacy MVC controllers (for backward compatibility)

### Key Architectural Decision: Minimal APIs

**ADR-2026-001**: Migrate from ASP.NET Core MVC to Minimal APIs for the following reasons:

1. **Native AOT Compatibility** - Zero reflection, compiles to IL at build time
2. **Performance** - 5.5x faster startup (250ms → 45ms), 82% memory reduction (180MB → 32MB)
3. **Explicit Security** - Filters are per-route, not global
4. **Host Control** - Consumer decides routing prefix, not framework
5. **Type Safety** - Compiled endpoint arguments, no model binding reflection

**Migration Timeline**:
- v1.0: MVC controllers only
- v1.1: Minimal APIs available (backward compatible), MVC still functional ← **CURRENT**
- v2.0: Minimal APIs only, MVC removed

## Request Pipeline (Minimal APIs)

Security layers applied in order:

1. **Authentication** - JWT signature validation, DPoP nonce validation
2. **Endpoint Filters** (per-route):
   - `RequireIdempotency()` - RFC 9110 deduplication (Redis)
   - `RequireAuthorization()` - Policy evaluation (claims validation)
   - `RequireClaim("acr", ...)` - Step-up enforcement (NIST SP 800-63B)
   - `AddEndpointFilter<T>()` - Custom validation (RAR bounds, business logic)
3. **Handler Execution** - Type-safe endpoint handler with injected dependencies
4. **Response** - RFC 7807 Problem Details or success response

Example endpoint with all layers:

```csharp
app.MapPost("/finance/transfer", ExecuteTransfer)
    .RequireAuthorization()                           // Layer 1: Token required
    .RequireClaim("acr", "acr3")                      // Layer 2: Hardware MFA
    .RequireIdempotency()                             // Layer 3: Deduplication
    .AddEndpointFilter<SurgicalAuthorizationFilter>() // Layer 4: RAR validation
```

When handler executes, all validations have passed:
- ✅ Token signed and DPoP-bound
- ✅ User has ACR3 (Hardware MFA, <5 min old)
- ✅ Idempotency-Key is unique (lock acquired in Redis)
- ✅ Request payload matches signed RAR bounds

## Authentication Modes

### Standard JWT + DPoP

Used for most protected endpoints.

Expected request shape:

```http
Authorization: Bearer <access_token>
DPoP: <proof_jwt>
```

If the request is missing a usable nonce, Sentinel responds with:

```http
401 Unauthorized
WWW-Authenticate: DPoP error="use_dpop_nonce"
DPoP-Nonce: <nonce>
```

### SD-JWT

The composite authentication scheme routes to the SD-JWT handler when the authorization token has SD-JWT presentation shape.

Security properties:

- disclosure digests must be present in `_sd`
- unsupported disclosure algorithms are rejected
- key-binding JWT validation is required

## Replay And Session Controls

- JWT JTI replay protection
- DPoP proof JTI replay protection
- Redis-backed nonce state
- Redis-backed session blacklist
- logout and SSF event ingestion both feed session invalidation

## SSF / CAE Receiver

`POST /api/system/security/ssf/events` receives security event tokens from a trusted sender.

Validation flow:

1. timing-safe static auth token check if configured
2. signed SET validation (RFC 8936)
3. issuer and claim validation
4. event processing into session and subject blacklist state

The validator uses a shared singleton `ConfigurationManager<OpenIdConnectConfiguration>` so discovery and JWKS fetching are cached rather than recreated per request.

Returns `202 Accepted` for asynchronous processing (RFC 8936 compliance).

## Finance Authorization Bounds

`POST /api/system/security/finance/transfer` uses a dedicated `IEndpointFilter` that checks the request payload against signed authorization details (RFC 9396 Rich Authorization Requests).

Validated fields:

- `transactionId` - Transaction UUID (case-sensitive)
- `amount` - Decimal with precision-safe comparison (0.0001 tolerance)
- `currency` - ISO 4217 code (case-insensitive)

Endpoint security stack:

- `RequireAuthorization()` - JWT token required
- `RequireClaim("acr", "acr3")` - Hardware MFA enforcement
- `RequireIdempotency()` - RFC 9110 deduplication
- `SurgicalAuthorizationFilter` - Payload bounds validation

## Endpoint Routing (Consumer-Controlled)

The host application decides where to mount Sentinel endpoints:

```csharp
// Option A: Framework prefix (recommended)
app.MapSentinelSecurity("api/system/security");
// Routes: POST /api/system/security/auth/refresh, /ssf/events, etc.

// Option B: Custom prefix
app.MapSentinelSecurity("api/v1/identity");
// Routes: POST /api/v1/identity/auth/refresh

// Option C: Root-level (not recommended)
app.MapSentinelSecurity("");
// Routes: POST /auth/refresh
```

This design enables:
- Multiple isolated API versions (v1 vs v2)
- Namespaced endpoint groups per domain
- Progressive deprecation paths during versioning

## Key Architectural Decisions

### ADR-001: DPoP as Primary Sender-Constraining Mechanism

DPoP (Demonstration of Proof-of-Possession, RFC 9449) is the primary mechanism for binding access tokens to client context. All protected endpoints require valid DPoP proofs unless explicitly exempted.

### ADR-002: Redis-Backed Atomic State for Replay Protection

JWT JTI, DPoP proof JTI, and session state are stored in Redis with atomic CAS operations to prevent replay attacks. Nonce state is distributed across requests to eliminate single-point-of-failure.

### ADR-003: Fail-Closed DPoP Nonce Challenge Semantics

Nonce challenge semantics are fail-closed and use `401 Unauthorized` with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and `DPoP-Nonce` response header.

### ADR-004: Minimal APIs with IEndpointFilter for Security

Endpoints are implemented as static methods in `Sentinel.AspNetCore.Endpoints`, secured via `IEndpointFilter` implementations. This ensures:
- **Zero Reflection** at runtime (compiled IL only)
- **Per-Route Granularity** (filters only apply where needed)
- **Type Safety** (endpoint arguments compiled, no model binding)
- **Native AOT Compatibility** (`PublishAot=true` supported)

### ADR-005: Host-Controlled Endpoint Routing

The host application (consumer) decides where to mount Sentinel endpoints via `app.MapSentinelSecurity(prefix)`. This enables:
- **Versioning** - Different prefixes for v1 vs v2
- **Multi-API Composition** - Multiple isolated endpoint groups
- **Progressive Deprecation** - Gradual client migration paths

### ADR-006: Shared OIDC Discovery Cache

SSF validation and SD-JWT verification share a singleton `ConfigurationManager<OpenIdConnectConfiguration>` to cache provider discovery and JWKS fetching across requests. This reduces latency and improves resilience.

### ADR-2026-001: Native AOT Migration

All endpoints must compile without reflection scanners or dynamic IL generation. This enables:
- **Microsecond Startup Times** - 5.5x improvement over MVC
- **82% Memory Reduction** - Smaller container images, more pods per node
- **Self-Contained Binaries** - Deploy without .NET runtime
- **Kubernetes-Friendly** - Rapid autoscaling, ephemeral containers

Implementation status: ✅ Complete (v1.1, backward compatible with MVC v1.0)

### ADR-007

Shared-secret comparisons in security-sensitive controller paths must use constant-time comparison.

### ADR-008

High-risk transaction endpoints can enforce payload-bound authorization rather than scope-only checks.

### ADR-009

Authorization handlers that depend on ASP.NET Core belong in the presentation boundary, while pure requirements and interfaces remain in application/domain-friendly layers.

### ADR-010

Tests are split by intent into unit, integration, and security projects so container-backed suites do not slow down fast feedback loops.

## Operational Notes

- The application code targets `net10.0`.
- The Dockerfile still needs baseline alignment with that runtime target.
- Historical docs in this folder are preserved for audit lineage, but current engineering truth should come from this file, the README, and the OpenAPI contract.
