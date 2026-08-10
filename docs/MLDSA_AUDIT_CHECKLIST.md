# ML-DSA (FIPS 204) Audit Checklist

> **Document ID**: SEC-0009
> **Status**: TEMPLATE — completed by the independent PQC reviewer during the
> gray-box/PQC phase (see `DAST_AND_PENTEST_PROGRAM.md` §3 and
> `PENTEST_ROE_TEMPLATE.md` §4).
> **Classification**: CONFIDENTIAL / INTERNAL USE ONLY

Sentinel implements post-quantum ML-DSA signature verification natively on
.NET 10 (`System.Security.Cryptography.MLDsa`, FIPS 204) and wires it into
DPoP key validation. This checklist drives the dedicated PQC review. Every item
must be marked PASS / FAIL / N/A with evidence (file:line, test name, log).

Reference surface:

| Component | Location |
|---|---|
| `IMlDsaSignatureVerifier` interface | `src/Sentinel.Security.Abstractions/Pqc/MlDsaSecurityKey.cs` |
| Native fail-closed verifier | `src/Sentinel.Infrastructure/Cryptography/MlDsaSignatureVerifier.cs` |
| DPoP `SignatureProvider` (verify-only) | `src/Sentinel.DPoP/Pqc/MlDsaSignatureProvider.cs` |
| Provider factory | `src/Sentinel.DPoP/Pqc/PqcCryptoProviderFactory.cs` |
| DPoP thumbprint / proof validation | `src/Sentinel.DPoP/DpopThumbprintComputer.cs`, `DpopProofValidator.cs` |
| Unit tests | `tests/Sentinel.Tests.Unit/Unit/MlDsaSignatureVerifierTests.cs`; `tests/Sentinel.Tests.DPoP/*` |

## 1. Algorithmic Correctness

| # | Check | Status | Evidence |
|---|---|---|---|
| 1 | Only FIPS 204 ML-DSA parameter sets used: **ML-DSA-44 / 65 / 87** (exactly those in the `AlgorithmMap`) | | |
| 2 | Key sizes enforced by the native `MLDsa.ImportMLDsaPublicKey` layer (size/format failure → `CryptographicException` → fail closed) | | |
| 3 | Verification uses native platform oracle only — no managed reimplementation | | |
| 4 | Known-answer / independent test vectors for at least ML-DSA-65 (or the deployed parameter set) | | |

## 2. Fail-Closed Semantics (the core security property)

| # | Check | Status | Evidence |
|---|---|---|---|
| 1 | Empty/whitespace algorithm → `false` + warning log | | |
| 2 | Host without native FIPS 204 support → **Critical** log + `false` (never degraded to classical) | | |
| 3 | Unknown algorithm identifier → `false` + warning | | |
| 4 | `CryptographicException`, `ArgumentException`, `InvalidOperationException` → `false`, no propagation to caller | | |
| 5 | Circuit through `Sentinel.DPoP`/DPoP middleware: any verifier `false` → request rejected (401), including the Bearer-downgrade negative path | | |

## 3. Key & Lifecycle Hygiene

| # | Check | Status | Evidence |
|---|---|---|---|
| 1 | Public keys injected via config/Key Vault (no hardcoded keys in `src/`) | | |
| 2 | Key rotation path exists (multi-key acceptance) and old keys removable without downtime | | |
| 3 | No private keys in the verifier path: `MlDsaSignatureProvider.Sign` throws `NotSupportedException` | | |
| 4 | Key-size/format rejection does not log bytes (no secret material in logs) | | |

## 4. Integration / Interop

| # | Check | Status | Evidence |
|---|---|---|---|
| 1 | DPoP `cnf.jkt` thumbprint computed over the **raw public key** matches RFC 9449 semantics | | |
| 2 | JWS verification honors the algorithm exactly as presented (no algorithm confusion), e.g. tokens signed with ML but verified as EdDSA are rejected | | |
| 3 | PQC path regression tests exist: sign→verify round-trip, mutated signature, wrong key, unsupported algorithm | | |

## 5. Non-Interference with Classical Crypto

| # | Check | Status | Evidence |
|---|---|---|---|
| 1 | TLS chains unchanged (classical until PQC TLS standards land); no hybrid handshakes half-enabled | | |
| 2 | App/ID suite continues to use Ed25519/ECDsa paths when `Pqc` not configured — no accidental coupling | | |
| 3 | CVD/fuzzing of the verifier entry point is covered by the regression suite | | |

## 6. Standards Reference

- FIPS 204 (Module-Lattice-Based Digital Signature Standard), Aug 2024.
- .NET 10 `System.Security.Cryptography.MLDsa` / `MLDsaAlgorithm` native implementation.
- RFC 9449 (DPoP) — `jkt`/`ath` binding, key-thumbprint semantics.

## 7. Sign-off

| Role | Name | Date | Verdict (PASS / PARTIAL / FAIL) |
|---|---|---|---|
| Independent PQC reviewer | | | |
| Security Working Group | | | |
| Release owner (Gate 5 blocker if FAIL) | | | |