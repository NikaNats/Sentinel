# Sentinel Documentation Suite

**Last Updated:** 2026-03-21
**Runtime Baseline:** .NET 10 (`net10.0`)
**Test Layout:** `Sentinel.Tests.Unit`, `Sentinel.Tests.Integration`, `Sentinel.Tests.Security`

Sentinel is a Zero Trust API that combines DPoP, session revocation, idempotency, step-up authorization, SD-JWT selective disclosure, SSF/CAE event ingestion, and RAR-style payload-bound authorization.

## Current Source of Truth

The following documents are the active references for the current codebase:

- `ARCHITECTURE.md`: current ADRs, middleware order, DPoP nonce semantics, replay handling.
- `OPENAPI_3_1.yaml`: current endpoint contract for the API surface in `src/Sentinel.Presentation/Controllers`.
- `SDK_LESS_INTEGRATION_GUIDE.md`: plain-HTTP client guidance for DPoP flows and protected endpoints.
- `BUILD_CONFIGURATION_GUIDE.md`: build, analyzer, and SDK guidance for the `net10.0` repo.
- `SRE_SOC_RUNBOOKS.md`: operational playbooks for auth failures, replay protection, nonce behavior, and Redis-backed controls.
- `LIVING_THREAT_MODEL.md`: threat inventory and mitigations, including replay, downgrade, session hijack, and infrastructure failure modes.
- `COMPLIANCE_AUDIT_MATRIX.md`: framework mapping and audit evidence.

## Current Feature Set

- DPoP-protected resource access with rotating `DPoP-Nonce` challenges.
- JWT replay detection and Redis-backed session blacklisting.
- Keycloak-backed profile, user lifecycle, logout, token refresh, and token exchange flows.
- SD-JWT verification and composite auth routing for selective disclosure scenarios.
- SSF event ingestion for session revocation and subject-level kill-switch behavior.
- RAR-style transaction-bound checks on `POST /v1/finance/transfer`.
- Split modular test projects with full green coverage across unit, integration, and security suites.

## Documentation Notes

- Historical gate and packaging documents remain in this folder because they capture audit context, but they should be read as historical snapshots unless they explicitly describe the current runtime or pipeline state.
- DPoP nonce challenge behavior is documented as `401 Unauthorized` with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and `DPoP-Nonce` response header where applicable.
- The repo is pinned to the stable .NET 10 SDK via `global.json`; docs should not describe .NET 11 as the active build baseline.
- The Docker packaging docs now explicitly call out the current image/runtime mismatch instead of treating it as release-ready.
- MFA management endpoints exist in the API contract but currently return `501 Not Implemented`; `OPENAPI_3_1.yaml` documents that stub state.

## Current Test Status

As of 2026-03-21, the modular test suites pass:

- `Sentinel.Tests.Unit`: 128 passed
- `Sentinel.Tests.Integration`: 22 passed
- `Sentinel.Tests.Security`: 13 passed

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
