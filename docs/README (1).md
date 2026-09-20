# Sentinel — Enterprise Documentation Suite

> **Suite ID**: SENT-DOCS-2026-09
> **Product**: `nikanats-sentinel` — a security-focused ASP.NET Core Web API enforcing sender-constrained token validation, aligned with FAPI 2.0 Baseline and Advanced hardening goals (per `README.md`).
> **Runtime baseline**: .NET 10 (`net10.0`, SDK pinned to **10.0.302** with `rollForward: disable` in `global.json`)
> **Evidence policy**: Every architectural statement, configuration key, algorithm identifier, status code, and default value in this suite traces to a concrete file in the repository. Source paths are cited inline (e.g., `src/Sentinel.DPoP/DpopProofValidator.cs`). No content is inferred from outside the codebase.

---

## 1. Suite Manifest

| # | Document | Audience | Contents |
|---|----------|----------|----------|
| 01 | [System Overview](./01-SYSTEM-OVERVIEW.md) | All | Product definition, solution topology, module inventory, technology stack, packaging model |
| 02 | [Architecture](./02-ARCHITECTURE.md) | Architects, Engineers | Hexagonal module topology, request pipeline, middleware ordering, composition root, fail-closed design principles, architectural invariants |
| 03 | [Security & Cryptography](./03-SECURITY-AND-CRYPTOGRAPHY.md) | Security, Auditors | DPoP validation state machine, ML-DSA (FIPS 204) PQC path, mTLS binding (RFC 8705), AES-256-GCM envelope encryption, key-ring rotation, timing-attack mitigations, algorithm governance |
| 04 | [API Reference](./04-API-REFERENCE.md) | Client Developers | Endpoint catalog, status-code matrix, RFC 7807 error type URIs, `WWW-Authenticate` challenge grammar, DPoP client integration walkthrough, SSF/backchannel-logout/token-exchange contracts, idempotency & rate-limit semantics |
| 05 | [Configuration Reference](./05-CONFIGURATION-REFERENCE.md) | Developers, DevOps | Every configuration section with defaults, validation ranges, startup validators, environment-variable mapping, production guardrails |
| 06 | [Deployment & Infrastructure](./06-DEPLOYMENT-AND-INFRASTRUCTURE.md) | DevOps, Platform | Container build (chiseled/distroless), docker-compose stack, Kubernetes manifests, Helm chart, Keycloak realm & FAPI 2.0 enforcement, Vault, observability stack |
| 07 | [Testing & Quality Assurance](./07-TESTING-AND-QUALITY-ASSURANCE.md) | QA, Engineers | Test suite taxonomy, CI gate graph (Gates 1–10), contract/schema-drift testing, security testing (timing, property-based, fuzz, mutation), chaos & load engineering, DAST program |
| 08 | [Operations Runbook](./08-OPERATIONS-RUNBOOK.md) | SRE, SOC, On-Call | Metrics catalog, log event-ID catalog, alert rules, fail-closed operator procedures, key-rotation runbook, troubleshooting decision trees |
| 09 | [Compliance & Traceability](./09-COMPLIANCE-AND-TRACEABILITY.md) | Compliance, Auditors | Standards traceability matrix (RFC 9449/8705/7638/9396/8936, FAPI 2.0, NIST SP 800-63B, FIPS 204, NIST SP 800-57), supply-chain integrity (SLSA controls), audit findings register |

## 2. Repository Shape (verified against the provided snapshot)

```text
nikanats-sentinel/
├── src/                 15 library projects (Sentinel.* — packable NuGet modules)
├── samples/             Reference host: Sentinel.Sample.MinimalApi (composition root)
├── tests/               13 test/benchmark/fuzz/load projects + k6/xk6 scripts + chaos experiments
├── infra/               helm chart, k8s manifests, keycloak realms, DAST tooling, observability stack
├── docs/                Pre-existing project documentation (architecture, runbooks, OpenAPI 3.1 contract)
├── publish-output/      Reference appsettings.json / web.config for published host
├── .github/workflows/   9 CI/CD gate workflows
└── .specify/            Spec-driven delivery artifacts (SPEC/PLAN/TASK-0001)
```

The solution file `Sentinel.slnx` enumerates **15 `src/` projects**, **1 sample host**, **1 DAST auth-proxy project**, and **13 test-side projects** (Contracts, Acceptance, Benchmarks, FuzzTests, Concurrency, DPoP, Integration, Load/AdversarialTestHost, Security, Session, Shared, SSF, Unit).

## 3. How to Read This Suite

- **New engineer onboarding**: 01 → 02 → 05 → 04.
- **Security audit / penetration-test preparation**: 03 → 09 → 07 → 08.
- **Platform / SRE onboarding**: 06 → 08 → 05.
- **Client integration (no SDK)**: 04 (wire formats and the end-to-end DPoP dance) → 05 (`DPoP` algorithm configuration that your proofs must satisfy).

## 4. Documentation Governance

| Rule | Implementation |
|------|----------------|
| Single source of truth | The code. Where this suite and `docs/*` in the repository disagree, the code wins; known divergences are logged in §4 of [09-COMPLIANCE-AND-TRACEABILITY.md](./09-COMPLIANCE-AND-TRACEABILITY.md). |
| Traceability | Each document cites repository-relative file paths for every non-obvious claim. |
| Contract drift control | `docs/OPENAPI_3_1.yaml` (contract version `2026-08-20`) is regenerated and diffed in CI ("Gate 5 — OpenAPI Schema Drift Audit", `.github/workflows/security-pipeline.yml`); API documentation changes must land with contract regeneration. |
| Versioning | Nerdbank.GitVersioning, base version `1.0.0`, `assemblyVersion.precision: major`, public releases cut from `main`/`release/*` (`version.json`). |

## 5. Snapshot Caveats (disclosed, not guessed)

1. `Makefile` content was not machine-readable in the provided snapshot (recorded as binary). Make targets documented in this suite are quoted from the "Make Targets" section of the repository `README.md`.
2. `Sentinel.public.snk` is present in the snapshot as a binary blob; the strong-name signing *model* is documented from `Directory.Build.props` and `README.md`.
3. Test-count figures (496 tests across 8 suites) are reported per the repository `README.md` "Implementation Status" table; this suite could not execute the suites (no .NET SDK in the documentation environment). Suite *structure* is verified from the `tests/` tree and CI matrix.
