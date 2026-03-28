# Sentinel Documentation

Last Updated: 2026-03-29
Code Baseline: net10.0 (SDK 10.0.201)
Architecture: Modular security platform with Minimal API integration surface

This folder is the authoritative documentation for Sentinel runtime behavior, security controls, integration contracts, and operations.

## Start Here

If you are new to the repo, read in this order:

1. ARCHITECTURE.md
2. SDK_LESS_INTEGRATION_GUIDE.md
3. OPENAPI_3_1.yaml
4. SRE_SOC_RUNBOOKS.md

## Document Map

| File | Audience | Purpose |
|---|---|---|
| ARCHITECTURE.md | Architects, senior engineers | System design, module boundaries, request pipeline, and extension model |
| BUILD_CONFIGURATION_GUIDE.md | Platform engineers, CI maintainers | Build baselines, analyzer policy, AOT considerations, and reproducibility |
| COMPLIANCE_AUDIT_MATRIX.md | Security, GRC, auditors | Standards mapping (RFC/NIST) to concrete implementation evidence |
| CONTAINER_BUILD_READINESS.md | DevOps, SRE | Current containerization readiness, blockers, and release checklist |
| LIVING_THREAT_MODEL.md | Security engineers, SOC | Threat inventory, controls, residual risk, and review cadence |
| OPENAPI_3_1.yaml | API consumers, SDK/tooling teams | Machine-readable API contract for Sentinel and sample routes |
| SDK_LESS_INTEGRATION_GUIDE.md | API consumers | End-to-end HTTP integration guide (no proprietary SDK required) |
| SRE_SOC_RUNBOOKS.md | SRE, SOC, on-call | Detection, triage, and response playbooks for common auth incidents |
| runbooks/auth-token-issuance.md | IAM operators | Token issuance and trust-chain operational runbook |
| archive/* | Historical audit artifacts | Legacy gate reports retained for traceability |

## Scope Definition

Sentinel consists of reusable security modules under src and a reference host under samples.

- Core modules: Sentinel.Security.Abstractions, Sentinel.DPoP, Sentinel.Session, Sentinel.SSF, Sentinel.SdJwt, Sentinel.Rar
- Integration modules: Sentinel.Redis, Sentinel.Keycloak, Sentinel.EntityFrameworkCore, Sentinel.Infrastructure
- Host integration layer: Sentinel.AspNetCore
- Reference host: samples/Sentinel.Sample.MinimalApi

## Documentation Quality Rules

These docs follow the same standards expected for production code:

1. Be code-accurate: statements must map to current source, not intended future behavior.
2. Be operationally useful: include incident response context, not only design rationale.
3. Be explicit about unknowns: identify blockers and residual risks instead of hand-waving.
4. Prefer stable contracts over internals for consumers; internals belong in architecture and runbooks.
5. Keep historical material in archive/, not mixed into active guidance.

## Release Maintenance Checklist

When shipping a new release, update at minimum:

1. ARCHITECTURE.md (pipeline or module changes)
2. OPENAPI_3_1.yaml (route or schema changes)
3. COMPLIANCE_AUDIT_MATRIX.md (evidence paths and control status)
4. LIVING_THREAT_MODEL.md (new threats or changed mitigations)
5. CONTAINER_BUILD_READINESS.md (runtime/packaging status)

## Related Root Files

For build truth and repository baselines, cross-check:

- global.json
- Directory.Build.props
- Directory.Packages.props
- Makefile
- docker-compose.yml
