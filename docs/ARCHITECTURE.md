# Sentinel Architecture

Last Updated: 2026-03-29
Runtime Baseline: net10.0

## 1. Executive Summary

Sentinel is a modular security platform focused on high-assurance API protection and standards-aligned identity flows. The architecture separates security contracts, protocol engines, integration adapters, and host-specific API wiring.

Core properties:

- Sender-constrained access via DPoP (RFC 9449)
- Replay resistance for access tokens and DPoP proofs
- Session invalidation and revocation propagation
- Rich authorization constraints (RAR-style payload checks)
- Shared security event ingestion (SSF/SET)
- Minimal API host integration via explicit endpoint mapping

## 2. Module Topology

### 2.1 Core Packages

- Sentinel.Security.Abstractions
    - Cross-module interfaces and contracts (caches, validators, options, result types)
- Sentinel.Domain
    - Domain entities, value objects, and invariants
- Sentinel.Application
    - Application-level orchestration and cross-domain use cases
- Sentinel.DPoP
    - DPoP validation engine and thumbprint computation
- Sentinel.Session
    - Session lifecycle and revocation logic
- Sentinel.SSF
    - Security event token processing and revocation side-effects
- Sentinel.SdJwt
    - Selective disclosure validation components
- Sentinel.Rar
    - Authorization details extraction and rule validation
- Sentinel.Security.Diagnostics
    - Canonical telemetry and security diagnostics primitives

### 2.2 Integration Packages

- Sentinel.Redis
    - Replay, nonce, and blacklist cache adapters
- Sentinel.Keycloak
    - Keycloak protocol integration and admin/token services
- Sentinel.EntityFrameworkCore
    - EF-backed security state implementations
- Sentinel.Infrastructure
    - Composition and operational services (DI, auth services, crypto, notifications)

### 2.3 Host Integration

- Sentinel.AspNetCore
    - Minimal API endpoint mapping extensions
    - Filters/middleware for idempotency and ACR step-up
    - Endpoint groups: auth, token exchange, SSF, backchannel logout

### 2.4 Reference Host

- samples/Sentinel.Sample.MinimalApi
    - Demonstrates framework endpoint mapping and business endpoint hardening
    - Shows encryption-at-rest, idempotency, ACR step-up, and RAR guardrail patterns

## 3. Request Flow (High-Level)

For protected routes in a host using Sentinel.AspNetCore:

1. Transport and host middleware execute (HTTPS, exception handling, auth/authorization middleware).
2. Authentication validates token envelope and principal.
3. DPoP checks bind proof to method/URL/time/JKT context.
4. Endpoint filters enforce route-specific policies:
     - RequireIdempotency()
     - RequireAcrStepUp(...)
     - custom domain filters (e.g., RAR bounds checks)
5. Business handler executes only after policy and protocol checks pass.
6. Response emits typed success or RFC7807 problem details.

## 4. Endpoint Mapping Model

Sentinel core endpoints are mounted by host choice:

```csharp
app.MapSentinelSecurity("api/system/security");
```

Mapped groups include:

- /auth/*
- /ssf/events
- /auth/token-exchange
- /auth/backchannel-logout

This enables:

- host-controlled versioning and namespace boundaries
- predictable integration in multi-service APIs
- no hard-coded global route ownership by framework internals

## 5. Security Control Architecture

### 5.1 DPoP and Replay

- Proof validation checks typ/alg/htm/htu/iat and JWK thumbprint semantics
- Proof JTI replay is stateful and fail-closed when backing stores are unavailable
- Nonce challenge flow uses 401 + WWW-Authenticate + DPoP-Nonce

### 5.2 Session Controls

- Session blacklist is used for local revocation enforcement
- Auth logout and SSF events converge on session invalidation behavior

### 5.3 Authorization Enforcement

- ACR step-up support for high-assurance operations
- Route-level idempotency requirements for state-changing operations
- Domain-level payload-bound validation (RAR-style) for finance transfer safety

### 5.4 Security Diagnostics

- Telemetry and event emission are centralized in Sentinel.Security.Diagnostics
- Canonical IP context hashing uses HMAC-based pseudonymization for privacy hardening

## 6. Design Decisions (Current)

1. Abstractions-first composition
     - Module contracts are defined in Sentinel.Security.Abstractions to avoid adapter lock-in.
2. Fail-closed for security-critical state dependencies
     - Replay and blacklist dependency failures are treated as security failures, not permissive bypasses.
3. Endpoint filter-based policy composition
     - High-risk checks are explicit per route; avoids opaque global behavior.
4. Host-controlled routing
     - Framework endpoints are namespaced by host, supporting phased migrations.
5. Diagnostics centralization
     - Security telemetry primitives are not duplicated across adapters.

## 7. Deployment and Operational Boundaries

Trust boundaries:

1. Client to API host
2. API host to cache/state stores
3. API host to identity provider metadata/JWKS
4. API host to security event senders (SSF)

Operationally sensitive dependencies:

- Redis/cache state for replay/nonce/session protections
- IdP discovery/JWKS availability
- Accurate service time for bounded token/proof validity logic

## 8. Known Constraints

- Container packaging is currently not fully production-ready in this repository because an active application Dockerfile is not present (see CONTAINER_BUILD_READINESS.md).
- Sample and framework endpoint OpenAPI contracts are maintained manually and require release-time updates.

## 9. Change Management Guidance

Any change in these areas requires architecture + compliance + threat model updates in the same pull request:

- auth pipeline order or semantics
- endpoint path contracts
- replay/nonce/session storage behavior
- DPoP, SSF, or RAR validation rules
- error behavior for fail-closed conditions
