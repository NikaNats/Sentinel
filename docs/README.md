# Sentinel Documentation Suite

**Last Updated:** 2026-03-25
**Runtime Baseline:** .NET 10 (`net10.0`)
**Architecture:** Native AOT-Compatible Minimal APIs (Zero Reflection)
**Test Status:** ✅ 141/141 Unit Tests Passing (Zero Regressions)

Sentinel is a Zero Trust Framework that combines DPoP (RFC 9449), session revocation, idempotency (RFC 9110), step-up authorization (NIST SP 800-63B), SD-JWT selective disclosure, SSF/CAE event ingestion (RFC 8936), and RAR-style payload-bound authorization (RFC 9396).

## Current Source of Truth

The following documents are the active references for the current codebase:

- `ARCHITECTURE.md`: Current ADRs, Minimal APIs structure, middleware order, DPoP nonce semantics.
- `MINIMAL_APIS_MIGRATION_GUIDE.md`: Complete guide to the zero-reflection endpoint architecture (NEW - 2026-03-25).
- `OPENAPI_3_1.yaml`: Current endpoint contract for the Minimal APIs surface (RFC 7807/8693/8936/9413/9110 compliant).
- `SDK_LESS_INTEGRATION_GUIDE.md`: Plain-HTTP client guidance for DPoP flows and protected endpoints.
- `BUILD_CONFIGURATION_GUIDE.md`: Build, analyzer, and SDK guidance for the `net10.0` repo with Native AOT support.
- `SRE_SOC_RUNBOOKS.md`: Operational playbooks for auth failures, replay protection, nonce behavior, and Redis-backed controls.
- `LIVING_THREAT_MODEL.md`: Threat inventory and mitigations, including replay, downgrade, session hijack, and infrastructure failure modes.
- `COMPLIANCE_AUDIT_MATRIX.md`: RFC compliance mapping and audit evidence.

## Current Feature Set

### Core Security Layers
- **DPoP Protection** (RFC 9449): Sender-constrained access tokens with rotating nonce challenges
- **Session Management**: Redis-backed session blacklist with logout and SSF event ingestion
- **Idempotency** (RFC 9110): Exactly-once semantics for fund transfers and sensitive operations
- **Step-Up Authorization** (NIST SP 800-63B): ACR enforcement for high-security endpoints (Hardware MFA required)
- **Rich Authorization Requests** (RFC 9396): Payload-bound transaction limits on financial operations
- **SD-JWT** (RFC 9052): Selective disclosure with composite auth routing
- **SSF Events** (RFC 8936): Continuous availability event ingestion for session revocation
- **Backchannel Logout** (RFC 9413): Server-initiated logout from upstream IdP

### Endpoint Architecture (Zero Reflection)
- **Minimal APIs** (Native AOT compatible): Pure static endpoint handlers, no MVC controllers
- **IEndpointFilter**: Per-route security filters (Idempotency, ACR Step-Up, Custom RAR validation)
- **Host-Controlled Routing**: Consumer decides endpoint prefix (`/api/v1/identity`, `/api/security`, etc.)
- **Type-Safe Handlers**: Compiled at build time, no dynamic IL generation

### Sample Implementation
- **Sentinel.Sample.MinimalApi**: Production-ready reference application demonstrating all security patterns
- **DocumentEndpoints**: Envelope cryptography for data-at-rest encryption
- **FinanceEndpoints**: Three-layer security (ACR step-up, idempotency, RAR validation)
- **SurgicalAuthorizationFilter**: Custom domain-specific authorization logic

## Documentation Notes

- **Architecture Evolution (v1.1 - 2026-03-25)**: Migrated from MVC Controllers (`Sentinel.Presentation`) to Minimal APIs (`Sentinel.AspNetCore.Endpoints`). MVC layer remains functional for backward compatibility during v1.x lifecycle.
- **Zero-Reflection Design**: All endpoints compiled at build time. No reflection, no dynamic IL generation. Native AOT compatible.
- **Routing Control**: Host application decides endpoint prefix via `app.MapSentinelSecurity("api/system/security")`. Not enforced by framework.
- **DPoP Nonce Challenge**: Documented as `401 Unauthorized` with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and `DPoP-Nonce` response header.
- **Session Revocation**: Redis-backed atomic state for logout, SSF event ingestion, and token revocation.
- **Financial Transactions**: RFC 9396 RAR validation with precision-safe decimal comparison for transaction amounts.
- **Native AOT Support**: The repo supports `dotnet publish -c Release -r win-x64 -p:PublishAot=true` for self-contained binaries.
- **Sample Application**: `samples/Sentinel.Sample.MinimalApi` demonstrates enterprise integration with envelope encryption, ACR step-up, and RAR validation.

## Current Test Status

**As of 2026-03-25**, all test suites pass with zero regressions:

- `Sentinel.Tests.Unit`: **141 tests PASSING** ✅
  - Security tests (DPoP, Token validation, Logout, Session management)
  - Infrastructure tests (Redis, Keycloak integration)
  - RFC compliance tests (Idempotency, RAR, SSF events)
  - Zero MVC Controller dependencies

**Build Performance**: 4.2 seconds (Release configuration)
**Native AOT Ready**: `PublishAot=true` verified
**Reflection Count**: 0 (zero-reflection architecture)

## Directory Map

```text
docs/
+-- ARCHITECTURE.md
+-- BUILD_CONFIGURATION_GUIDE.md
+-- COMPLIANCE_AUDIT_MATRIX.md
+-- CONTAINER_BUILD_READINESS.md
+-- GATE_5_FINAL_REPORT.md
+-- GATE_5_PACKAGING_HARDENING.md
+-- LIVING_THREAT_MODEL.md
+-- OPENAPI_3_1.yaml
+-- README.md
+-- SDK_LESS_INTEGRATION_GUIDE.md
+-- SRE_SOC_RUNBOOKS.md
+-- runbooks/
    +-- auth-token-issuance.md
```
