# Compliance And Audit Matrix

> **Document ID**: CMP-0001
> **Status**: DOCUMENTATION REVIEW / APPROVED PROCEDURE (execution evidence is separate)
> **Scope**: Sentinel core libraries, ASP.NET Core middleware, and reference sample
> **Compliance Baseline**: FAPI 2.0 Baseline/Advanced · NIST 800-63B AAL3 · FedRAMP High · GDPR · FIPS 204 (ML-DSA)

---

## 1. Methodology

This matrix maps international security standards, regulatory frameworks, and control objectives directly to concrete cryptographic and architectural evidence in the Sentinel repository.

### Status Legend:
- **Implemented:** Control code and/or repository test evidence is present; this label does not imply that the current review reran the test or a live environment.
- **Partial:** Foundational framework exists, but final deployment integration is pending.
- **Gap:** No verified implementation exists in the current baseline.

---

## 2. Standards Mapping

| Standard | Control Theme | Status | Primary Evidence |
|---|---|---|---|
| **RFC 6750** | Bearer token usage and security at API boundary | Implemented | `src/Sentinel.AspNetCore/Endpoints/AuthEndpoints.cs` |
| **RFC 7807** | Standardized Problem Details for HTTP API error shapes | Implemented | `src/Sentinel.AspNetCore/Errors/ErrorCodes.cs` and global exceptions |
| **RFC 8693** | OAuth 2.0 Token Exchange endpoint (External IdP Federation) | Implemented | `src/Sentinel.AspNetCore/Endpoints/TokenExchangeEndpoints.cs` |
| **RFC 8936** | Shared Signals and Events (SSF/SET) continuous risk ingestion | Implemented | `src/Sentinel.AspNetCore/Endpoints/SsfEndpoints.cs`, `src/Sentinel.SSF/` |
| **RFC 9110** | Idempotency semantics (`Idempotency-Key`) for safe state retries | Implemented | `src/Sentinel.AspNetCore/Filters/IdempotencyFilter.cs` |
| **RFC 9396** | Rich Authorization Requests (RAR) fine-grained payload checks | Implemented | `src/Sentinel.Rar/`, `samples/Sentinel.Sample.MinimalApi/Filters/SurgicalAuthorizationFilter.cs` |
| **RFC 9413** | OIDC Backchannel Logout session termination signaling | Implemented | `src/Sentinel.AspNetCore/Endpoints/BackchannelLogoutEndpoints.cs` |
| **RFC 9449** | DPoP sender-constrained token validation and nonce challenges | Implemented | `src/Sentinel.DPoP/`, `src/Sentinel.AspNetCore/Middleware/DpopValidationMiddleware.cs` |
| **RFC 9901** | Selective Disclosure JWT (SD-JWT) presentation and verification | Implemented | `src/Sentinel.SdJwt/`, `tests/Sentinel.Tests.Integration/Integration/SdJwtFlowIntegrationTests.cs` |
| **NIST 800-63B** | Authentication Assurance (AAL3) via WebAuthn + ACR step-up | Implemented | `src/Sentinel.AspNetCore/Filters/AcrStepUpAuthorizationFilter.cs`; Keycloak realm config (`infra/keycloak/realms/sentinel.json`, `sentinel-dast.json`): `government-aal3-browser` flow (password + WebAuthn UV=required + conditional TOTP recovery), `acr.loa.map` acr3, MDS3 attestation, FR-14 lockout. The repository documents prior live Keycloak 26.6.4 verification; this review did not rerun it (`docs/KEYCLOAK_FAPI_ENFORCEMENT.md`). |
| **FIPS 204** | Post-Quantum Cryptographic signatures (ML-DSA) validation | Implemented | `src/Sentinel.Infrastructure/Cryptography/MlDsaSignatureVerifier.cs` |
| **FAPI 2.0 Security Profile (OIDF Conformance)** | Third-party verifiable conformance against the OIDF suite (DPoP, PAR, private_key_jwt) | Partial | `.github/workflows/fapi-conformance-gate.yml` (pre-flight readiness → suite → evidence handling), `infra/dast/scripts/run-fapi-conformance.sh`, `infra/staging/verify-fapi-readiness.sh`, `infra/k8s/staging/` + `infra/staging/provision-staging-tls.sh` (publicly routable AS). No hosted-suite result or certificate is claimed by this review; the first result remains pending (`docs/OIDF_FAPI_CONFORMANCE_RUNBOOK.md`). |
| **NIST 800-53 CA-8 / Constitution §VIII.4** | Independent white-box penetration test before every major release (OWASP API Top 10 + FAPI 2.0 + auth flows) | Partial | Program + tailored RoE + release gate: `docs/PENTEST_PROGRAM.md` (10 mandated attack scenarios, CVSS SLAs, findings JSON schema), `docs/PENTEST_ROE_SENTINEL.md` (signed engagement terms), `.github/workflows/pentest-gate.yml` (evidence existence + recency ≤90d + no open CRITICAL/HIGH), `infra/staging/verify-pentest-readiness.sh` (TLS 1.3-only, Redis auth, admin console, security headers); execution by independent certified team pending |

---

## 3. Control Objective Coverage

| Objective | Status | Notes / Primary Evidence |
|---|---|---|
| **Sender-Constrained Token Use** | Implemented | Cryptographic verification of DPoP proof signature and `cnf.jkt` binding in `DpopProofValidator.cs`. |
| **Replay Resistance** | Implemented | Atomic Redis-backed `jti` cache with fail-closed behavior on timeout (`RedisJtiReplayCache.cs`). |
| **Session Invalidation** | Source-implemented paths; host/provider effectiveness unverified | Local session blacklisting and Keycloak logout calls exist on SSF/logout paths; Keycloak false results are discarded by the SSF processor, so 202 is not proof of provider-side revocation. |
| **Event-Driven Risk Response** | Source-implemented intake; live acceptance/effectiveness unverified | SSF event intake and token validation exist; effective Keycloak revocation requires deployment and live verification. |
| **Payload-Bound Authorization** | Implemented | Precision-safe RAR validation matching JSON payloads against signed bounds (`FinancialAuthorizationMatcher.cs`). |
| **Timing Attack Mitigation** | Implemented | Constant-Time Failure Padding + Cryptographic Jitter Injection (0-15ms) in `DpopValidationMiddleware.cs` ($p\text{-value} > 0.05$). |
| **Exception Shielding (DoS Protection)** | Implemented | Robust `try-catch` boundaries on token/proof parsers preventing unhandled crashes on malformed headers (`DpopValidationMiddleware.TryExtractProofDetails`). |
- **Systematic Concurrency Verification** | Implemented as a test shape | The Concurrency matrix leg performs the Coyote IL rewrite and runs the rewritten assembly through VSTest (`IdempotencyConcurrencyTests.cs`); this is not proof that every race or deadlock is absent. |
| **Network Chaos Resilience** | Implemented | Docker-based Testcontainers + Toxiproxy tests simulating packet loss, timeouts, and network latency jitter (`RedisResilienceChaosTests.cs`). |
| **Production Container Hardening** | Implemented | Multi-stage, distroless reference test-harness Dockerfile running as the chiseled base image's pre-configured non-privileged user `app` (UID 1654) with `DOTNET_EnableDiagnostics=0` (`samples/Sentinel.Sample.MinimalApi/Dockerfile`; not a shipping product artifact). |
| **Post-Quantum Cryptography** | Implemented | Native .NET 10 FIPS 204 `MLDsa` cryptographic signature verification (`MlDsaSignatureVerifier.cs`); repository tests provide evidence, but this review did not rerun them or establish live cryptographic proof. |
| **Persistent vs Ephemeral State** | Implemented as an opt-in adapter | The optional hybrid session-blacklist adapter can add PostgreSQL write-through when a host explicitly registers the required L2/L3 dependencies; the inspected reference host does not visibly register the decorator or `SentinelSecurityDbContext`. PostgreSQL is not an active reference-host path in this evidence, and nonce/JTI state remain Redis-backed. |
| **JWKS Key Rotation & Grace Period** | Implemented as test/telemetry evidence; live refresh behavior unverified | `RotatingJwksServer` test fixture + `JwksRotationIntegrationTests`; kid-miss and refresh counters are recorded, but the inspected reference callback does not call `RequestRefresh` or retry; grace-period retention is an IdP/operator responsibility. |
| **TLS Certificate Reload** | Implemented | `KestrelCertificateReloader` + `ServerCertificateSelector`; initial load, options-change reload and a debounced directory file watcher (covers Kubernetes symlink swaps). Verify the served certificate/gauge after rotation. |
| **mTLS Certificate Cache Rotation** | Implemented | `MtlsCertificateCache` keyed by raw-PEM SHA-256 + sliding expiration; rotation = cache miss + parse; bounded by `SizeLimit` (10k); unit tests for rotation/eviction. |
| **Envelope Lazy Re-wrap** | Implementation present; production persistence unresolved | `IEnvelopeEncryptionService.DecryptEnvelope` → `EnvelopeDecryptionResult(PlainText, RequiresRewrap, RewrappedCipher)`; service-side re-wrap and metrics exist, but the inspected registration has a concrete-service DI gap and no production caller persists returned bytes. |

---

## 4. Evidence Index

### 4.1 Endpoint & Middleware Layer (Ports)
- `src/Sentinel.AspNetCore/Endpoints/SentinelEndpointExtensions.cs`
- `src/Sentinel.AspNetCore/Endpoints/AuthEndpoints.cs`
- `src/Sentinel.AspNetCore/Endpoints/TokenExchangeEndpoints.cs`
- `src/Sentinel.AspNetCore/Endpoints/SsfEndpoints.cs`
- `src/Sentinel.AspNetCore/Endpoints/BackchannelLogoutEndpoints.cs`
- `src/Sentinel.AspNetCore/Middleware/DpopValidationMiddleware.cs` (includes Timing & Exception Shielding)
- `src/Sentinel.AspNetCore/Middleware/MtlsBindingMiddleware.cs` (includes mTLS binding verification)
- `src/Sentinel.AspNetCore/Infrastructure/SecurityInvariantsStartupFilter.cs` (Production fail-fast architectural guardrails)

### 4.2 Protocol, Parsing & Security Modules
- `src/Sentinel.DPoP/` (DPoP Proof Validation Engine)
- `src/Sentinel.Session/` (Session State Machine)
- `src/Sentinel.SSF/` (Shared Signals Event Processor)
- `src/Sentinel.SdJwt/` (Selective Disclosure Presentation Verifier)
- `src/Sentinel.Rar/` (Rich Authorization Request Evaluator)
- `src/Sentinel.Infrastructure/Cryptography/MlDsaSignatureVerifier.cs` (Native FIPS 204 ML-DSA Signature Verifier)
- `src/Sentinel.Infrastructure/Cryptography/AesGcmEncryptionService.cs` (Envelope encryption + lazy re-wrap)
- `src/Sentinel.Infrastructure/Cryptography/CryptographyOptions.cs` (KeyRing + ActiveKeyId config)
- `src/Sentinel.EntityFrameworkCore/Stores/HybridSessionBlacklistCache.cs` (PostgreSQL + L2-Port Write-Through Cache)
- `src/Sentinel.AspNetCore/Infrastructure/KestrelCertificateReloader.cs` (TLS initial/options-change reload; inspected file watcher disabled)
- `src/Sentinel.AspNetCore/Stores/MtlsCertificateCache.cs` (mTLS cert cache)

### 4.3 Advanced Testing & Verification Suites
- `tests/Sentinel.Tests.Concurrency/IdempotencyConcurrencyTests.cs` (Coyote Systematic Concurrency Tests)
- `tests/Sentinel.Tests.Security/Chaos/ChaosSentinelApiFactory.cs` (Toxiproxy Chaos Test Fixture)
- `tests/Sentinel.Tests.Security/Chaos/RedisResilienceChaosTests.cs` (Chaos Resilience Tests)
- `tests/Sentinel.Tests.Security/Security/DpopTimingSideChannelTests.cs` (Welch's T-Test Timing Side-Channel Tests)
- `tests/Sentinel.Benchmarks/` (Micro-benchmarking Suite)
- `tests/Sentinel.FuzzTests/` (Generative Fuzz Testing Harness)
- `tests/Sentinel.Tests.Unit/Unit/MlDsaSignatureVerifierTests.cs` (Natively verified Post-Quantum Cryptographic Tests)
- `tests/Sentinel.Tests.Unit/Unit/AesGcmEncryptionServiceTests.cs` (Envelope re-wrap + rotation + legacy)
- `tests/Sentinel.Tests.Unit/Unit/MtlsCertificateCacheTests.cs` (Rotation + eviction + capacity)
- `tests/Sentinel.Tests.Integration/Integration/HybridSessionBlacklistCacheIntegrationTests.cs` (Containerized multi-tier persistence and caching tests)
- `tests/Sentinel.Tests.Integration/Integration/Cryptography/JwksRotationIntegrationTests.cs` (JWKS rotation + grace + retirement)
- `Sentinel.Tests.Acceptance/` (Reqnroll E2E Acceptance Tests for FAPI 2.0 Financial Transfers and CAEP SSF Session Revocation)

---

## 5. Recommended Audit Verification Procedure

1.  **Cryptographic Build Verification:**
    ```powershell
    dotnet restore Sentinel.slnx --locked-mode
    dotnet build Sentinel.slnx -c Release -p:SignSentinelRelease=true
    ```
2.  **Core Regression Verification (Unit Suite including Post-Quantum checks):**
    ```powershell
    dotnet test tests/Sentinel.Tests.Unit/Sentinel.Tests.Unit.csproj -c Release
    ```
3.  **Systematic Concurrency Verification (Coyote):**
    ```powershell
    # IL-rewrite the candidate assemblies, then run the programmatic TestingEngine suites (1000 iterations).
    dotnet tool restore
    dotnet build tests/Sentinel.Tests.Concurrency/Sentinel.Tests.Concurrency.csproj -c Release -p:RunCoyoteRewrite=true
    dotnet test tests/Sentinel.Tests.Concurrency/Sentinel.Tests.Concurrency.csproj -c Release --no-build -p:SkipGetBuildVersion=true -p:NBGV_Disable=true
    ```
4.  **Network Chaos & Timing Side-Channel Verification:**
    ```powershell
    dotnet test tests/Sentinel.Tests.Security/Sentinel.Tests.Security.csproj --filter "FullyQualifiedName~Chaos|FullyQualifiedName~Timing" -c Release
    ```
5.  **Multi-Tier Integration Cache Verification (PostgreSQL + Redis containerized tests):**
    ```powershell
    dotnet test tests/Sentinel.Tests.Integration/Sentinel.Tests.Integration.csproj --filter "FullyQualifiedName~HybridSession" -c Release
    ```
6.  **Acceptance & E2E Verification (Reqnroll):**
    ```powershell
    # The entire lifecycle is fully automated (containers, host, tests, teardown).
    dotnet test tests/Sentinel.Tests.Acceptance/Sentinel.Tests.Acceptance.csproj -c Release
    ```

---

## 6. Known Gaps and Exceptions

1.  **OpenAPI Contract Synchronization:** The OpenAPI specification (`docs/OPENAPI_3_1.yaml`) is currently maintained manually. Automated CI drift detection against active route mapping remains a future enhancement.
2.  **Keycloak Flow Orchestration:** Some FAPI 2.0 orchestration steps (such as PAR and PKCE authorization code exchanges) are natively handled by the Keycloak identity provider, while the API acts strictly as the validating Resource Server.
3.  **DAST realm Redis runs unauthenticated** inside the virtual network (mirrors dev compose) — guarded by the `redis-unauthenticated.yaml` Nuclei template so over-exposure fails the gate.
4.  **DAST scanner auth is client_secret-based** (no x509/MTLS scanner identity) — the proxy holds the secret; the mTLS path is covered by the integration suites.

---

## 7. Compliance Roadmap & Action Items

- [x] Add and validate a rootless, distroless reference test-harness Dockerfile (`samples/Sentinel.Sample.MinimalApi/Dockerfile`; not a shipping product artifact).
- [x] Implement constant-time mitigation and cryptographic jitter on failure paths to eliminate timing side-channels.
- [x] Configure the Coyote-rewritten VSTest path for the Concurrency matrix leg; this documents the test shape, not a proof that every race or deadlock is absent.
- [x] Implement FIPS 204 compliant post-quantum cryptographic signature validation using .NET 10 native APIs.
- [x] Configure the documented Testcontainers/Toxiproxy/LitmusChaos test paths; successful execution and production resilience require separate evidence.
- [x] **Dynamic Application Security Testing (DAST) capability documented:** `.github/workflows/dast-release-gate.yml` defines OWASP ZAP + Nuclei against the compose stack (DPoP Signing Proxy `infra/dast/auth-proxy`, `sentinel-dast` realm), with HIGH/CRITICAL evaluation configured. The current diagram/documentation review did not run this workflow; Program + RoE + ML-DSA audit checklists are documented (`docs/DAST_AND_PENTEST_PROGRAM.md`, `docs/PENTEST_ROE_TEMPLATE.md`, `docs/MLDSA_AUDIT_CHECKLIST.md`). First CI runs should be used non-blockingly to baseline alert-filter exceptions (see §5 step 6).
- **Container image scanning and signing:** the current `security-pipeline.yml` has no container-image scan or signing job. Gate 9 is deterministic NuGet compilation and package verification; `publish-nuget` creates a package SBOM, a build-provenance attestation, publishes NuGet packages, and archives them for 90 days. Any separate image scan described here is an operator procedure, not a verified `security-pipeline.yml` result.
- [x] **Test Suite Matrix Completeness (workflow shape):** `test-suites` defines all registered unit/integration test projects (including `DPoP`, `Session`, `SSF`, `Concurrency`) plus the Docker-enabled `acceptance-e2e` (Reqnroll FAPI/CAEP evidence) job; the seven-assembly VSTest batch was not green in the current review, so this does not assert passing execution.
- [x] **Browser-mediated FAPI 2.0 E2E (Playwright) capability documented:** `Sentinel.Tests.Integration.Federation` defines the full interactive flow (PAR with nonce + `dpop_jkt`, real browser login, DPoP-bound token exchange with `cnf.jkt` verification, userinfo) plus PAR reuse/expiry/direct-authorize/PKCE/DPoP-nonce negatives against a live Keycloak 26.6.4 container. The repository reports 8/8 passing, but the current review did not independently rerun that browser flow; assertion contract and deviations from ADR-2026-004: `docs/KEYCLOAK_FAPI_ENFORCEMENT.md`.
- [ ] Implement CI-based automated OpenAPI drift detection to verify contract alignment with route mappings.
- [ ] **OIDF FAPI 2.0 Conformance PASSED:** provision staging Keycloak (`infra/k8s/staging/`, `infra/staging/provision-staging-tls.sh` — public CA required), pass `infra/staging/verify-fapi-readiness.sh`, then run `fapi-conformance-gate.yml` against the hosted suite; the gate auto-commits `fapi-certificate.pdf` + `fapi-evidence-manifest.txt` under `docs/compliance/` on PASSED (link from this matrix; prerequisites and triage matrix: `docs/OIDF_FAPI_CONFORMANCE_RUNBOOK.md`).
- [ ] **Independent Penetration Test (Constitution §VIII.4):** select independent certified team (OSCP/CEH/CISSP, `docs/PENTEST_PROGRAM.md` §4), sign RoE (`docs/PENTEST_ROE_SENTINEL.md`), deploy production-parity staging (`infra/staging/verify-pentest-readiness.sh` must pass), execute the ten mandated scenarios, remediate CRITICAL ≤24h / HIGH ≤7d, archive `pentest-report-*.pdf` + `pentest-findings-*.json` + `pentest-retest-*.pdf` + SHA-256 manifest under `docs/compliance/`; release gate `.github/workflows/pentest-gate.yml` must pass with zero open CRITICAL/HIGH.
- [ ] **WebAuthn AAL3 ceremony tests:** Playwright-based ceremony suite (FR-08..FR-14) against the Keycloak realm config landed in this round; enrollment-first, UV=required, conditional TOTP recovery, FR-10 MDS3 negative-testing strategy decision pending (CDP cannot emit attestation statements; MDS3 fetch requires egress). The Playwright + Testcontainers + CallbackServer infrastructure proven by the browser-mediated FAPI 2.0 suite is the foundation this builds on.
