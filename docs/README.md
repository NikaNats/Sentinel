# Sentinel Documentation Index

> **Document ID**: DOC-0001
> **Last Updated**: 2026-06-16
> **Code Baseline**: .NET 10.0 (SDK 10.0.302)
> **Architecture**: Modular security platform with decoupled Hexagonal (Ports & Adapters) integration surface

This folder serves as the authoritative, FAPI 2.0-compliant documentation suite for Sentinel's runtime behavior, cryptographic security controls, integration contracts, and SRE operations.

---

## Start Here

If you are new to the repository, read these documents in the recommended order of onboarding:

1.  **[ARCHITECTURE.md](ARCHITECTURE.md):** Deep-dive into system design, module boundaries, concrete adapter decoupling, and the defensive-in-depth request pipeline.
2.  **[SDK_LESS_INTEGRATION_GUIDE.md](SDK_LESS_INTEGRATION_GUIDE.md):** Complete language-agnostic HTTP/REST integration guide with DPoP proof wire-formats (no proprietary SDK required).
3.  **[OPENAPI_3_1.yaml](OPENAPI_3_1.yaml):** Formal, machine-readable OpenAPI 3.1 specification for SDK generation and gateway routing.
4.  **[SRE_SOC_RUNBOOKS.md](SRE_SOC_RUNBOOKS.md):** Operational monitoring, alerting, incident response playbooks, and cache-degradation recovery checklists.

---

## Document Map

| File | Audience | Purpose | Status |
|---|---|---|---|
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Architects, Senior Engineers | System topology, dependency inversion model, request pipeline, and ADRs. | Verified |
| **[BUILD_CONFIGURATION_GUIDE.md](BUILD_CONFIGURATION_GUIDE.md)** | Platform Engineers, CI/CD | MSBuild configurations, CPM versioning, strong-name signing, and AOT setup. | Verified |
| **[COMPLIANCE_AUDIT_MATRIX.md](COMPLIANCE_AUDIT_MATRIX.md)** | GRC, Security Auditors | Mapping of international standards (RFC/NIST) to concrete code evidence. | Verified |
| **[KEYCLOAK_FAPI_ENFORCEMENT.md](KEYCLOAK_FAPI_ENFORCEMENT.md)** | IAM Operators, Platform Engineers | Keycloak 26.6.4 realm policy structure, 26.x executor IDs, DPoP runtime support, and documented enforcement gaps. | Verified |
| **[CONTAINER_BUILD_READINESS.md](CONTAINER_BUILD_READINESS.md)** | DevOps, SRE | Multi-stage, rootless, and hardened Docker container release readiness. | **RELEASE-READY** |
| **[DISTRIBUTED_CONCURRENCY_SPEC.md](DISTRIBUTED_CONCURRENCY_SPEC.md)** | Architects, SRE | Distributed state atomicity, TOCTOU mitigation, Coyote & Chaos Mesh verification. | **APPROVED** |
| **[OIDF_FAPI_CONFORMANCE_RUNBOOK.md](OIDF_FAPI_CONFORMANCE_RUNBOOK.md)** | DevOps, Architects, Security | OIDF FAPI 2.0 conformance gate: network topology, Keycloak hardening, suite API integration, evidence custody, failure triage. | **ACTIVE** |
| **[LIVING_THREAT_MODEL.md](LIVING_THREAT_MODEL.md)** | Security Engineers, SOC | Threat inventory (STRIDE/DREAD), mitigations, and residual risks. | Active |
| **[OPENAPI_3_1.yaml](OPENAPI_3_1.yaml)** | API Consumers, Gateway | Machine-readable API contracts and schemas for gateway routing. | Active |
| **[SDK_LESS_INTEGRATION_GUIDE.md](SDK_LESS_INTEGRATION_GUIDE.md)** | API Consumers | Handshake protocols, Nonce challenge-response, and raw HTTP examples. | Active |
| **[SRE_SOC_RUNBOOKS.md](SRE_SOC_RUNBOOKS.md)** | SRE, On-Call Operators | Incident triage, logging, telemetry, and disaster recovery playbooks. | Active |
| **[CRYPTO_LIFECYCLE_RUNBOOK.md](CRYPTO_LIFECYCLE_RUNBOOK.md)** | Crypto Operators, SRE | JWKS rotation, TLS hot reload, mTLS cache, envelope re-wrap, metrics, alerting. | Active |
| **`runbooks/auth-token-issuance.md`** | IAM Operators | Token issuance, trust-chain validation, and key-rotation playbooks. | Active |
| **`archive/*`** | Compliance Auditors | Historical audit artifacts retained for end-to-end traceability. | Archived |

---

## Scope Definition

Sentinel consists of reusable, stateless security modules under `src/` and a reference host under `samples/`:

-   **Core Modules (Ports):** `Sentinel.Security.Abstractions`, `Sentinel.DPoP`, `Sentinel.Session`, `Sentinel.SSF`, `Sentinel.SdJwt`, `Sentinel.Rar`, `Sentinel.Security.Diagnostics`
-   **Integration Modules (Adapters):** `Sentinel.Redis` (optional), `Sentinel.Keycloak`, `Sentinel.EntityFrameworkCore` (optional), `Sentinel.Infrastructure`
-   **Host Integration Layer (Glue):** `Sentinel.AspNetCore`
-   **Reference Host (Composition Root):** `samples/Sentinel.Sample.MinimalApi`
-   **Verification & Test Suites:** `Sentinel.Tests.Unit`, `Sentinel.Tests.Integration`, `Sentinel.Tests.Security`, `Sentinel.Tests.Acceptance` (Reqnroll E2E)

---

## Documentation Quality Rules

These documents are treated with the same engineering rigor expected of production code:

1.  **Code Accuracy:** All architectural and configuration statements must map to the current source code, not intended future behavior.
2.  **Operationally Actionable:** Include actual, copy-pasteable commands, triage steps, and incident response context, not just design theory.
3.  **Transparency on Risks:** Be explicit about trade-offs, security bounds, and remaining residual risks instead of obfuscation.
4.  **Traceability:** Maintain exact cross-referencing between specification files, compliance matrixes, and execution tests.
5.  **Clean History:** Keep obsolete materials strictly in the `archive/` directory to avoid dilution of active guidance.

---

## Release Maintenance Checklist

When shipping a new release, the releasing engineer **must** verify and update at minimum:

- [ ] **ARCHITECTURE.md** (pipeline or module adjustments)
- [ ] **OPENAPI_3_1.yaml** (route or schema changes)
- [ ] **COMPLIANCE_AUDIT_MATRIX.md** (control statuses and code evidence paths)
- [ ] **LIVING_THREAT_MODEL.md** (new threats, mitigations, or changed risk scores)
- [ ] **CONTAINER_BUILD_READINESS.md** (container packaging, base image updates, and security scans)
- [ ] **Acceptance & E2E Suite (Reqnroll)** successfully validated against live running host
