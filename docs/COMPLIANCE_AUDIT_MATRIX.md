# Compliance And Audit Matrix

> **Document ID**: CMP-0001  
> **Status**: APPROVED  
> **Scope**: Sentinel core libraries, ASP.NET Core middleware, and reference sample  
> **Compliance Baseline**: FAPI 2.0 Baseline/Advanced · NIST 800-63B AAL3 · FedRAMP High · GDPR

---

## 1. Methodology

This matrix maps international security standards, regulatory frameworks, and control objectives directly to concrete cryptographic and architectural evidence in the Sentinel repository.

### Status Legend:
- **Implemented:** Control exists in current code paths, fully covered by automated testing.
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
| **NIST 800-63B** | Authentication Assurance (AAL3) via WebAuthn + ACR step-up | Implemented | `src/Sentinel.AspNetCore/Filters/AcrStepUpAuthorizationFilter.cs` |

---

## 3. Control Objective Coverage

| Objective | Status | Notes / Primary Evidence |
|---|---|---|
| **Sender-Constrained Token Use** | Implemented | Cryptographic verification of DPoP proof signature and `cnf.jkt` binding in `DpopProofValidator.cs`. |
| **Replay Resistance** | Implemented | Atomic Redis-backed `jti` cache with fail-closed behavior on timeout (`RedisJtiReplayCache.cs`). |
| **Session Invalidation** | Implemented | Immediate session blacklist on logout and SSF-triggered revocation paths (`SsfEventProcessor.cs`). |
| **Event-Driven Risk Response** | Implemented | Real-time SSF event intake, token validation, and session termination (`SsfEventProcessor.cs`). |
| **Payload-Bound Authorization** | Implemented | Precision-safe RAR validation matching JSON payloads against signed bounds (`FinancialAuthorizationMatcher.cs`). |
| **Timing Attack Mitigation** | Implemented | Constant-Time Failure Padding + Cryptographic Jitter Injection (0-15ms) in `DpopValidationMiddleware.cs` ($p\text{-value} > 0.05$). |
| **Exception Shielding (DoS Protection)** | Implemented | Robust `try-catch` boundaries on token/proof parsers preventing unhandled crashes on malformed headers (`DpopValidationMiddleware.TryExtractProofThumbprint`). |
| **Systematic Concurrency Verification** | Implemented | Concurrency race tests simulated 1000-fold using Microsoft Coyote task scheduler (`IdempotencyConcurrencyTests.cs`). |
| **Network Chaos Resilience** | Implemented | Docker-based Testcontainers + Toxiproxy tests simulating packet loss, timeouts, and network latency jitter (`RedisResilienceChaosTests.cs`). |
| **Production Container Hardening** | Implemented | Multi-stage, distroless `Dockerfile` running as unprivileged user `sentinel` (UID 1654) with `DOTNET_EnableDiagnostics=0` (`src/Sentinel.AspNetCore/Dockerfile`). |

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

### 4.2 Protocol, Parsing & Security Modules
- `src/Sentinel.DPoP/` (DPoP Proof Validation Engine)
- `src/Sentinel.Session/` (Session State Machine)
- `src/Sentinel.SSF/` (Shared Signals Event Processor)
- `src/Sentinel.SdJwt/` (Selective Disclosure Presentation Verifier)
- `src/Sentinel.Rar/` (Rich Authorization Request Evaluator)

### 4.3 Advanced Testing & Verification Suites
- `tests/Sentinel.Tests.Concurrency/IdempotencyConcurrencyTests.cs` (Coyote Systematic Concurrency Tests)
- `tests/Sentinel.Tests.Security/Chaos/ChaosSentinelApiFactory.cs` (Toxiproxy Chaos Test Fixture)
- `tests/Sentinel.Tests.Security/Chaos/RedisResilienceChaosTests.cs` (Chaos Resilience Tests)
- `tests/Sentinel.Tests.Security/Security/DpopTimingSideChannelTests.cs` (Welch's T-Test Timing Side-Channel Tests)
- `tests/Sentinel.Benchmarks/` (Micro-benchmarking Suite)
- `tests/Sentinel.FuzzTests/` (Generative Fuzz Testing Harness)

---

## 5. Recommended Audit Verification Procedure

1.  **Cryptographic Build Verification:**
    ```powershell
    dotnet restore Sentinel.slnx --locked-mode
    dotnet build Sentinel.slnx -c Release -p:SignSentinelRelease=true
    ```
2.  **Core Regression Verification (Unit Suite):**
    ```powershell
    dotnet test tests/Sentinel.Tests.Unit/Sentinel.Tests.Unit.csproj -c Release
    ```
3.  **Systematic Concurrency Verification (Coyote):**
    ```powershell
    cd tests/Sentinel.Tests.Concurrency/bin/Release/net10.0
    dotnet coyote test Sentinel.Tests.Concurrency.dll -m Sentinel.Tests.Concurrency.IdempotencyConcurrencyTests.TestConcurrentIdempotencyAcquisition -i 1000 -ms 200 --portfolio-mode fair
    ```
4.  **Network Chaos & Timing Side-Channel Verification:**
    ```powershell
    dotnet test tests/Sentinel.Tests.Security/Sentinel.Tests.Security.csproj --filter "FullyQualifiedName~Chaos|FullyQualifiedName~Timing" -c Release
    ```

---

## 6. Known Gaps and Exceptions

1.  **OpenAPI Contract Synchronization:** The OpenAPI specification (`docs/OPENAPI_3_1.yaml`) is currently maintained manually. Automated CI drift detection against active route mapping remains a future enhancement.
2.  **Keycloak Flow Orchestration:** Some FAPI 2.0 orchestration steps (such as PAR and PKCE authorization code exchanges) are natively handled by the Keycloak identity provider, while the API acts strictly as the validating Resource Server.

---

## 7. Compliance Roadmap & Action Items

- [x] Add and validate a production-grade, rootless, distroless Dockerfile (`src/Sentinel.AspNetCore/Dockerfile`).
- [x] Implement constant-time mitigation and cryptographic jitter on failure paths to eliminate timing side-channels.
- [x] Automate systematic concurrency and network chaos engineering verification in the test suite.
- [ ] Implement CI-based automated OpenAPI drift detection to verify contract alignment with route mappings.
