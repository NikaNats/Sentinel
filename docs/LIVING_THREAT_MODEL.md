# Sentinel Living Threat Model

> **Document ID**: LTM-0001
> **Last Updated**: 2026-06-16
> **Classification**: CONFIDENTIAL / INTERNAL USE ONLY
> **Review Cycle**: Quarterly + on any major protocol modification


## 1. System Context

Sentinel protects API access using high-performance, sender-constrained tokens, real-time session revocation propagation, and deep-verification pipelines. The scope of this threat model covers the following core modules:

- `Sentinel.DPoP` (DPoP Proof Validation Engine)
- `Sentinel.Session` (Session Lifecycle Management)
- `Sentinel.SSF` (Shared Signals Ingestion & CAEP Event Processor)
- `Sentinel.Rar` (RFC 9396 Rich Authorization Request Evaluator)
- `Sentinel.Redis` (Decoupled Distributed State Adapter)
- `Sentinel.AspNetCore` (Middleware Pipeline, Exception Shielding, and Failure Padding)
- `Sentinel.Infrastructure` (Envelope Cryptography & FIPS 140-3 Compliance Layer)


## 2. Protected Assets

1.  **Access and Refresh Tokens:** Cryptographically bound bearer credentials.
2.  **DPoP Proof Integrity:** Ephemeral signatures and proof private-key binding semantics (`cnf.jkt`).
3.  **Session Blacklist & Replay Records:** Redis/Relational database-backed state cache.
4.  **SSF Event Trust Decisions:** Webhook signature and SHARED token verification secrets.
5.  **Authorization Detail Constraints:** Signed transaction bounds (RFC 9396) for financial transfers.
6.  **Security Telemetry & Metrics:** Anonymous diagnostics and correlation trace IDs (W3C).


## 3. Trust Boundaries

1.  **External Untrusted Clients ──► API Host:** Crosses the public Internet boundary (TLS 1.3 terminated at Ingress).
2.  **API Host ──► Caching/State Backends (Redis):** Internal boundary (secured via private network policy + mTLS).
3.  **API Host ──► Identity Provider (Keycloak JWKS):** External boundary (secured via pinned HTTPS and metadata caching).
4.  **Event Sender (IdP Webhook) ──► SSF Ingress:** External boundary (secured via signature checks + constant-time token comparison).
5.  **Internal Class Library Boundaries:** Strict logical decoupling between `Sentinel.Security.Abstractions` (Ports) and concrete Adapters.


## 4. Threat Inventory (STRIDE + DREAD)

| Threat ID | Threat Description | Category | Impact | Likelihood | Primary Mitigation |
|---|---|---|---|---|---|
| **T-01** | Access token replay / hijacking | Repudiation | High | Medium | JTI replay checks with fail-closed behavior on timeout. |
| **T-02** | DPoP proof replay / MITM interception | Repudiation | High | Medium | Proof JTI replay state + Nonce challenge-response rotation. |
| **T-03** | Nonce bypass / reuse under concurrent load | Tampering | High | Medium | Atomic Nonce consumption via Redis transaction compare-and-delete. |
| **T-04** | Authorization payload tampering (RAR bypass) | Tampering | High | Medium | Case-insensitive, precision-safe RAR-style transfer bounds filter. |
| **T-05** | SSF forgery or stale event replay | Spoofing | High | Medium | Signature/issuer/timing checks + constant-time webhook auth token compare. |
| **T-06** | **Timing Side-Channel Attacks (Timing Oracle)** | Info Leak | High | Low | **Constant-Time Failure Padding** + **Cryptographic Jitter Injection (0-15ms)** in DPoP middleware ($p\text{-value} > 0.05$). |
| **T-07** | **Denial of Service (DoS) via Malformed Tokens** | Availability | High | Medium | **Localized Exception Shielding** on JWT/JSON parsers preventing process-crashing unhandled exceptions. |
| **T-08** | **Concurrency / Lock Races on Sliding Nonces** | Tampering | High | Low | **Systematic Concurrency Testing** via Microsoft Coyote (1000+ thread interleaving iterations). |
| **T-09** | Telemetry privacy leakage via naive IP logging | Info Leak | Medium | Low | HMAC-SHA256 based `SecurityContextHasher` for privacy-hardened pseudonymization. |
| **T-10** | Cache outage on security-critical checks | Availability | High | Medium | **Fail-closed semantics** on Redis/DB timeouts (rejects requests immediately). |


## 5. Key Mitigations in Code

### 5.1 DPoP and Replay Protection
- **DPoP Proof Validation:** Strict signature, type (`dpop+jwt`), `htm`, `htu`, and `iat` window (±60s) validation in `DpopProofValidator.cs`.
- **Constant-Time Failure Padding:** All failed requests in `DpopValidationMiddleware` are padded up to a minimum floor (100ms) and randomized with **0-15ms of cryptographic jitter** to fully wash out sub-millisecond cryptographic execution deltas.
- **Exception Shielding:** Localized `try-catch` blocks on JSON/JWT parsing entries (specifically `TryExtractProofThumbprint`) catch `ArgumentException` and `SecurityTokenException` and return `null`, preventing process-crashing DoS exploits on malformed headers.

### 5.2 Session and Revocation
- **Continuous Session Blacklisting:** In-request authorization paths check `ISessionBlacklistCache`. SSF webhooks and local logout paths converge on session invalidation.
- **Fail-Closed State Boundaries:** If the distributed cache times out, the store throws `ReplayCacheUnavailableException` / `SessionBlacklistUnavailableException`, failing closed with a secure HTTP 503/500 instead of bypassing security checks.
- **RFC 7807 Challenge Serialization:** Standardized JWT validation failures (such as session termination) write formatted `ProblemDetails` payloads via `OnChallenge` to prevent unhandled 500 information leaks while maintaining clear, testable context for the client.

### 5.3 SSF Integrity & Concurrency Verification
- **Constant-Time Ingress Authentication:** Webhook authentication tokens are validated using `CryptographicOperations.FixedTimeEquals` to prevent timing side-channel exploits.
- **Coyote Systematic Verification:** Thread-scheduling concurrency races (such as parallel nonce consumption) are systematically tested 1000-fold using Microsoft Coyote to mathematically prove the absence of race conditions.
- **Toxiproxy Chaos Verification:** Network latencies, packet losses, and timeouts are simulated in integration environments using Testcontainers to verify pipeline resilience.
- **Automated Reqnroll E2E Acceptance Testing:** End-to-end scenarios (such as financial wire transfers and CAEP session revocations) are executed continuously to mathematically verify that the deployed infrastructure behaves exactly as defined by the security models, preventing any drift in compliance.


## 6. Fail-Closed Expectations

The following are **mandatory, non-negotiable** security behaviors:

1.  **Replay or Blacklist state unavailable:** Reject request immediately (return 503/500).
2.  **Invalid/stale/malformed DPoP proof:** Reject request immediately (return 401).
3.  **Invalid SSF token or signature:** Reject webhook processing (return 401).
4.  **Missing/invalid required Nonce:** Challenge immediately with a fresh Nonce (return 401), do not bypass.


## 7. Detection and Monitoring Priorities

1.  **Replay Detection Spikes:** Surges in duplicate `jti` or proof `jti` alerts.
2.  **DPoP Failure Ratio Increase:** Elevated rate of `401 Unauthorized` with `invalid_dpop_proof`.
3.  **`use_dpop_nonce` Surge Patterns:** Abnormal volume of Nonce challenge-responses (possible replay scanning).
4.  **SSF Rejection Trends:** Webhook signature or timing validation failures.
5.  **Cache Dependency Leakage/Latency/Error Rates:** Real-time monitoring of Redis response times and connection failures.


## 8. Residual Risks

1.  **Identity Provider Outage:** Outages in Keycloak JWKS endpoints will degrade trust-refresh and token-validation operations (acceptable dependency risk, mitigated via JWKS caching).
2.  **OpenAPI Contract Drift:** The OpenAPI contract is manually maintained and can drift from active route mappings if not release-gated (mitigated via route-audit CI gate).


## 9. Review Cadence and Triggers

Review and update this threat model:
- At each major release.
- After any modification to the authentication/authorization pipeline.
- After introducing new endpoint filters or changing cache/state storage behavior.
- Following any security incident postmortem.

### Required Synchronized Updates on Change:
1. `docs/ARCHITECTURE.md` (Design and pipeline changes)
2. `docs/COMPLIANCE_AUDIT_MATRIX.md` (Evidence paths and standards mapping)
3. `docs/BUILD_CONFIGURATION_GUIDE.md` (Build baselines and release gates)
