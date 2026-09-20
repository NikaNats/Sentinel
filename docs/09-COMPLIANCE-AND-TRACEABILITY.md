# 09 — Compliance & Traceability

> This document maps external standards to concrete implementation and test evidence inside the repository, records supply-chain integrity controls, and logs audit findings observed during documentation. Standards identifiers follow the annotations used by the codebase itself (e.g., source comments cite "RFC 9413" for backchannel logout and "RFC 8936" for SSF/SET; "RFC 9901" for SD-JWT). Companion repository artifacts: `docs/COMPLIANCE_AUDIT_MATRIX.md` (40+ checklist items), `docs/LIVING_THREAT_MODEL.md` (21 threats / 7 categories), `docs/MLDSA_AUDIT_CHECKLIST.md`, `docs/KEYCLOAK_FAPI_ENFORCEMENT.md`, `docs/compliance/README.md`.

## 1. Standards Traceability Matrix

### 1.1 RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)

| Requirement | Implementation evidence | Test evidence |
|---|---|---|
| Proof is a JWT with `typ: dpop+jwt` | `DpopProofValidator` check #5 (`invalid_typ`); middleware `DpopTypValue` | `DpopProofValidatorTests` |
| `jwk` public key in header; private material rejected | checks #6–#10 (`missing_jwk`, `private_jwk_rejected`, `invalid_jwk`); middleware `oct`-confusion block (event 2002) | `WeakKeyTests`, `AlgorithmResilienceTests` |
| `htm`/`htu` binding to request | checks #13–#14; htu normalization (query/fragment stripped, default port dropped, trailing slash trimmed) | `DpopProofValidatorTests`, `ProtocolFuzzTests` |
| `iat` freshness + single-use `jti` | checks #16–#17 (`ProofLifetimeSeconds=60`, skew 10 default), #21 atomic replay mark with TTL = lifetime+skew | `TemporalBoundaryTests`, `JtiSetNxContractTests` |
| Server nonce challenge–response (`use_dpop_nonce`, `DPoP-Nonce` header) | Middleware challenge/rotation flow; Lua CAS-delete consumption (`RedisDpopNonceStore.ConsumeNonceScript`) | `NonceLuaScriptContractTests`, `DpopValidationMiddlewareTests`, E2E `dpop-dance.sh` |
| `ath` binding for refresh with DPoP | `KeycloakDpopProofFactory.CreateProof(…, accessToken)` stamps `ath = base64url(SHA-256(token))` on refresh calls | `KeycloakDpopProofFactoryTests` |
| `cnf.jkt` access-token binding | checks #19–#20 (`missing_cnf_jkt`, `jkt_mismatch`) | `DpopProofValidatorTests`, `RealParPkceDpopFlowTests` |
| Error/challenge grammar | §2.3 of [03](./03-SECURITY-AND-CRYPTOGRAPHY.md) (exact `WWW-Authenticate` strings, `algs=` parameter) | `SecuritySchemeContractTests`, nuclei `sentinel-dpop-*` templates |

### 1.2 RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication & Certificate-Bound Tokens

| Requirement | Evidence |
|---|---|
| `cnf.x5t#S256` = base64url(SHA-256(DER cert)) comparison | `MtlsBindingMiddleware` (`SHA256.HashData(cert.RawData)` → `Base64Url`) with `FixedTimeEquals` |
| Thumbprint taken only from authenticated token, never client input | `TryGetThumbprintFromAuthenticatedPrincipal` (fail-closed 403 on missing `cnf`) |
| Certificate chain + clientAuth EKU validation | `ValidateCertificateChain` (OID `1.3.6.1.5.5.7.3.2`, offline revocation, `ExcludeRoot`) |
| mTLS-bound tokens at the IdP | Keycloak client `sentinel-m2m-worker` attribute `tls.client.certificate.bound.access.tokens: true` (`infra/keycloak/realms/sentinel.json`) |
| Tests | `MtlsBindingMiddlewareTests`, `MtlsCertificateCacheTests`, Gate 10 filter `MtlsCertificateRotation` |

### 1.3 RFC 7638 — JWK Thumbprint

`DpopThumbprintComputer`: canonical member sets per key type (EC `crv/kty/x/y`, RSA `e/kty/n`, ML-DSA `kty/x`), lexicographic insertion, source-generated JSON serialization, SHA-256, base64url. Tests: `DpopThumbprintComputerTests`.

### 1.4 FAPI 2.0 (Baseline & Advanced hardening goals)

| Control | Evidence |
|---|---|
| Sender-constrained tokens only (DPoP or mTLS) | DPoP middleware + `MtlsBindingMiddleware` DPoP-bound/Bearer downgrade rejection (`/errors/dpop-binding-required`) |
| Algorithm restriction (asymmetric, strong) | Global allow-list; JwtBearer pinned `PS256/ES256`; startup validators; prohibited-algorithm exceptions ("FAPI 2.0 violation" messages) |
| PKCE S256 + PAR at the IdP | Realm client attribute `pkce.code.challenge.method: S256`; `KC_FEATURES: dpop,par`; `RealParPkceDpopFlowTests` (Playwright browser flow) |
| Zero clock skew on access tokens | Sample host `ClockSkew = TimeSpan.Zero` (non-Development) |
| `acr` claim presence + step-up for sensitive ops | `AcrValidationMiddleware`; `AcrStepUpAuthorizationFilter` (`acr3` + 5-min `auth_time`) |
| Realm-wide FAPI policy | Keycloak client policy `fapi2-security-policy` → `fapi2-security-profile`, condition `any-client` |
| Conformance tooling | `infra/fapi-conformance/` stack, `infra/keycloak/fapi2-conformance-profile.json`, `run-fapi-conformance.sh`, `fapi-conformance-gate.yml`, `verify-fapi-readiness.sh`, `docs/OIDF_FAPI_CONFORMANCE_RUNBOOK.md` |
| DAST proof of enforcement | nuclei `sentinel-dpop-bearer-downgrade`, `sentinel-dpop-missing-proof`; ZAP DPoP auth script |

### 1.5 RFC 9396 — OAuth 2.0 Rich Authorization Requests (RAR)

`Sentinel.Rar`: `RarExtractor` (parses `authorization_details`), `RarValidator` (polymorphic matcher routing by type/weight), `FinancialAuthorizationMatcher` (monetary bounds with `MonetaryPrecisionTolerance = 0.0001m`, `MaxAuthorizationDetailsCount = 100`), host-side enforcement via `SurgicalAuthorizationFilter` for `urn:sentinel:finance:transfer` (403 `/errors/authorization-bounds-exceeded`). Tests: `RarExtractorTests`, `RarValidatorExceptionTests`, `RarPropertyTests`, `DpopAndRarPropertyTests`, acceptance feature scenarios (in-bounds 200 / out-of-bounds 403).

### 1.6 SSF / CAEP event intake (source-cited RFC 8936)

`SsfEventProcessor` + `SsfEndpoints`: SET signature/issuer validation (`ISsfTokenValidator`), temporal bounding (`MaxEventAgeSeconds` 300 + skew 300), CAEP event types `session-revoked` / `user-status-changed` / `credential-change` (exact `https://schemas.openid.net/secevent/caep/...` URIs), fail-closed whole-SET semantics, webhook shared-secret with constant-time compare, route obfuscation (404). Tests: `SsfEventProcessorTests`, `SsfEventProcessorResiliencyTests`, `SsfIntegrationTests`, `SsfEndpointsTests`; acceptance evidence via `acceptance-e2e` job ("FAPI + CAEP Evidence").

### 1.7 OIDC Back-Channel Logout (source-cited RFC 9413)

`BackchannelLogoutEndpoints` (anonymous, form `logout_token`), `LogoutTokenValidator` (signature/events/sid extraction), blacklist TTL = `SsoSessionMaxLifespanSeconds` (8 h default), 200-on-invalid non-disclosure, 503 on persistence failure. Tests: `BackchannelLogoutEndpointsTests`, `LogoutTokenValidatorTests`, `BackchannelLogoutContractTests` (+ `backchannel-logout-token.schema.json`), acceptance `SessionRevocation.feature`.

### 1.8 OAuth Token Exchange & refresh rotation

`KeycloakTokenExchangeService` posts `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with `subject_token_type`/`requested_token_type = urn:ietf:params:oauth:token-type:access_token`; `KeycloakTokenRefreshService` performs `grant_type=refresh_token` and detects rotation; reuse detection surfaces `/errors/token-theft-detected`. Tests: `TokenExchangeWithRealKeycloakTests`, `TokenResponseContractTests` (+ schema), `KeycloakServicesTests`.

### 1.9 NIST SP 800-63B — authenticator assurance & step-up

ACR/AAL ranking model (`AcrRankingOptions`, supports `acr*` and `aal*` mappings), step-up filter citing the SP in its doc-comment, `auth_time` recency enforcement (5-min default), WebAuthn ceremony tests (`WebAuthnAal3CeremonyTests`, `WebAuthnMds3Tests`, `WebAuthnBruteForceTests`).

### 1.10 FIPS 204 (ML-DSA) & FIPS posture

Native `System.Security.Cryptography.MLDsa` verification; `MLDsa.IsSupported` platform gate; fail-closed verifier default; exact public-key sizes 1312/1952/2592; verify-only provider (`Sign` throws `NotSupportedException`); `FipsConfiguration` (`UseLegacyFipsThrow=false`, `/proc/sys/crypto/fips_enabled` detection). Evidence: `MlDsaSignatureVerifierTests`, `docs/MLDSA_AUDIT_CHECKLIST.md`, `docs/CRYPTO_LIFECYCLE_RUNBOOK.md`.

### 1.11 NIST SP 800-57 — key management

Versioned key ring, active-key designation, lazy re-wrap with telemetry (`crypto.lazy_rewraps_total`, `crypto.keyring.active_key_mismatch`), legacy-key migration path, hot reload without restart (`CryptographyOptions` doc-comment claims FedRAMP High alignment via auditable key-version metadata). Evidence: `AesGcmEncryptionServiceTests`, Gate 10 `EnvelopeRewrap` filter.

### 1.12 RFC 7807 / RFC 6750 — error & challenge formats

All error bodies are `application/problem+json` with the type-URI catalog in [04 §1.3](./04-API-REFERENCE.md); bearer challenges follow RFC 6750 §3 shape (`Bearer error="insufficient_user_authentication", error_description=…, acr_values=…, max_age=…` — filter doc-comment cites the RFC section).

### 1.13 W3C Trace Context & OTel semantic conventions

`CorrelationIdMiddleware` uses `Activity.Current.TraceId`; histogram named in seconds per OTel conventions (`auth.token.validation.duration`, unit `s` — explicit FIX comment in `AuthTelemetry`); `deployment.environment`/`service.version` resource attributes in the host.

## 2. Supply-Chain & Build Integrity (SLSA-oriented controls)

| Control | Evidence |
|---|---|
| Pinned toolchain | `global.json` SDK 10.0.302, `rollForward: disable` |
| Deterministic, reproducible builds | `ContinuousIntegrationBuild`, `Deterministic` (README build table), `EmbedUntrackedSources` |
| Locked dependencies | `RestorePackagesWithLockFile=true`; all CI restores `--locked-mode`; single NuGet source with mapping (`nuget.config`) |
| Transitive CVE pinning | `SSH.NET` forced to 2026.0.0 (CVE-2026-48798 note in `Directory.Packages.props`) |
| Secret scanning | Gate 1 TruffleHog v3.95.9 |
| SAST | Gate 2 Semgrep (justified `nosemgrep` suppressions inline) |
| Dependency audit | Gate 3 (`dotnet` NuGet audit) |
| SBOM | Gate 6/7 Anchore `sbom-action` v0.17.9 (SPDX), attached to release images via `cosign attach sbom` |
| IaC scanning | Gate 8 Checkov |
| Image scanning | Gate 9 Trivy v0.36.0 + SARIF artifact; `.trivyignore` requires expiry+ticket per entry (currently empty — "base images are kept up to date") |
| Image provenance | Keyless **cosign** signature (Sigstore) on `release/*`; `cosign verify` gated on workflow identity regexp + `token.actions.githubusercontent.com` OIDC issuer |
| Assembly integrity | Strong-name hybrid model (`SignSentinelRelease`, `Sentinel.snk` from CI secret; PublicSign fallback with committed `Sentinel.public.snk`) |
| Contract integrity | OpenAPI generated from the running host (Gate 4), drift-audited against committed baseline (Gate 5), compatibility contract tests |
| Minimal runtime | Chiseled/distroless image, non-root UID 1654, diagnostics IPC disabled, invariant globalization |

## 3. OWASP-Aligned Control Mapping (DAST coverage crosswalk)

| Risk class | Preventive control (code) | Detective control (DAST/tests) |
|---|---|---|
| Auth downgrade (DPoP→Bearer) | `/errors/dpop-binding-required` 401 | `sentinel-dpop-bearer-downgrade.yaml` |
| Missing proof on DPoP scheme | 401 `missing_dpop_proof` + constant-time padding | `sentinel-dpop-missing-proof.yaml` |
| Injection (SQLi/XSS/SSRF) | Parameterized EF Core, strict JSON encoder (`JavaScriptEncoder.Default`, G-XSS comment), TLS-1.3-only outbound handler | `sentinel-sqli.yaml`, `sentinel-xss.yaml`, `sentinel-ssrf.yaml` |
| Mass assignment | Explicit record DTOs, source-generated JSON contexts (no dynamic binding) | `sentinel-mass-assignment.yaml` |
| Security misconfiguration (headers/TLS) | `SecurityHeadersMiddleware` fixed header set | `sentinel-security-headers.yaml`, `tls-version.yaml`, `infrastructure-tls-audit.sh` |
| Insecure dependencies (infra) | Pinned image versions (Keycloak 26.6.4, Redis 7.4, Postgres 17) | `keycloak-version-cve.yaml`, `redis-unauthenticated.yaml` |
| DoS / resource abuse | Body/proof size caps, L1 anti-flood, dual-partition rate limits, Kestrel connection/data-rate limits | `RateLimitingBypassAttemptsTests`, adversarial k6 scripts, spike CRD (20k) |
| Replay | Atomic SET-NX caches (token + proof jti), nonce CAS-delete | `JtiSetNxContractTests`, `TokenReplayDetected` alert path |
| Sensitive data in logs | Daily-keyed HMAC hashing of IP/jti/sid/sub | `PrivacyPreservingHasherTests` |

## 4. Audit Findings Register (documentation-time observations)

Severity scale: **Info** (documented trade-off), **Low** (hardening opportunity), **Medium** (should fix before GA of the affected feature). All findings are traceable; none is speculative.

| ID | Sev | Finding | Evidence | Recommendation |
|---|---|---|---|---|
| F-01 | Low | The *sample* host registers `DefaultPrivacyKeyManager` with a hardcoded 32-byte master pepper | `samples/Sentinel.Sample.MinimalApi/Program.cs` (bottom of file) | Production hosts must register a real `IPrivacyKeyManager` (e.g., Vault-backed via `VaultPrivacyHardeningExtensions` / `PrivacyKeyManager`). Acceptable for a sample; call out in integration docs |
| F-02 | Medium | `EdDSA` is in the global algorithm allow-list and the validator maps `kty: OKP → EdDSA`, but `DpopThumbprintComputer` implements only EC/RSA/ML-DSA — an EdDSA proof passes signature checks and then fails at thumbprint computation (`unsupported_key_type`), so EdDSA DPoP is effectively unusable end-to-end | `src/Sentinel.DPoP/DpopProofValidator.cs` (kty switch) vs `src/Sentinel.DPoP/DpopThumbprintComputer.cs` (no OKP branch) | Either add the RFC 7638 OKP member set (`crv/kty/x`) or remove `EdDSA` from the allow-list until implemented; add a validator test for OKP |
| F-03 | Info | MFA/TOTP + recovery-code endpoints are mapped but return 501 | `AuthEndpoints.cs` (`Produces(StatusCodes.Status501NotImplemented)` ×5) | Documented as stubs; gate client expectations (OpenAPI marks them 501) |
| F-04 | Info | `docs/ARCHITECTURE.md` §4.1 states the failure floor as "e.g. 100ms"; the code constant is `TargetFailureFloorMs = 120` | `DpopValidationMiddleware.cs` vs `docs/ARCHITECTURE.md` | Update the repo doc to 120 ms (this suite documents the code value) |
| F-05 | Info | Code-coverage thresholds (>80%/>90%) are targets, **not** CI-enforced gates — explicitly disclosed by the repository | `docs/CODE_COVERAGE_GUIDE.md` §"Coverage is not currently enforced as a CI gate" | Roadmap item per the guide; add `CollectCoverage`/`Threshold` step when ready |
| F-06 | Info | `DPoPOptions.RequireNonce` defaults to `false` (nonce enforced on challenge rather than always-required) | `DPoPOptions.cs` | For FAPI Advanced deployments consider `true`; Helm prod currently ships defaults + algorithm pins only |
| F-07 | Info | Local compose stack ships well-known dev credentials (`postgres/postgres`, Keycloak `admin/admin`) and the DAST dance script embeds a DAST-realm client secret | `docker-compose.yml`, `dpop-dance.sh` (`sentinel-dast-scanner` secret) | Dev/DAST-only by design (ephemeral realms, isolated stack); never reuse in shared environments — TruffleHog gate covers source hygiene |
| F-08 | Info | `Makefile` content was not machine-readable in the provided snapshot (recorded binary); make-target documentation derives from README | Snapshot artifact | Re-export `Makefile` as UTF-8 text in the next snapshot |

## 5. Compliance Framework Cross-Reference (repository artifact map)

| Framework / program | Repository artifact |
|---|---|
| OAuth 2.0 / JWT / DPoP / FAPI 2.0 checklist (40+ items) | `docs/COMPLIANCE_AUDIT_MATRIX.md` |
| Threat model (21 threats, 7 categories, likelihood×impact, residual risk) | `docs/LIVING_THREAT_MODEL.md` |
| FedRAMP-style risk acceptance trail | `.trivyignore` policy header (expiry + ticket required per entry) |
| FIPS 204 PQC audit | `docs/MLDSA_AUDIT_CHECKLIST.md` |
| Crypto/PKI lifecycle governance | `docs/CRYPTO_LIFECYCLE_RUNBOOK.md` |
| K8s secrets governance | `docs/KUBERNETES_SECRET_MANAGEMENT_STRATEGY.md` |
| Pentest governance | `docs/PENTEST_PROGRAM.md`, `docs/PENTEST_ROE_SENTINEL.md`, `docs/PENTEST_ROE_TEMPLATE.md`, `pentest-gate.yml` |
| DAST governance | `docs/DAST_AND_PENTEST_PROGRAM.md`, `dast-release-gate.yml` |
| Conformance evidence | `docs/OIDF_FAPI_CONFORMANCE_RUNBOOK.md`, `fapi-conformance-gate.yml` |
| Packaging hardening history | `docs/archive/GATE_5_FINAL_REPORT.md`, `docs/archive/GATE_5_PACKAGING_HARDENING.md` |
| Spec-driven delivery audit trail | `.specify/specs|plans|tasks/*`, `.specify/memory/constitution.md` |

## 6. Auditor's Verification Path (reproduce key claims locally)

```bash
# Algorithm governance — both allow-lists and the startup validator
grep -rn "GloballyAllowedAlgorithms" src/ | sed -n '1,10p'
grep -rn "CRITICAL SECURITY INVARIANT" src/ | sed -n '1,10p'

# Fail-closed store semantics
grep -rn "UnavailableException" src/Sentinel.Redis/Stores src/Sentinel.EntityFrameworkCore/Stores | head

# Constant-time failure padding constants
grep -n "TargetFailureFloorMs\|GetInt32(0, 16)" src/Sentinel.AspNetCore/Middleware/DpopValidationMiddleware.cs

# ML-DSA fail-closed matrix
grep -n "return false; // Fail-Closed" src/Sentinel.Infrastructure/Cryptography/MlDsaSignatureVerifier.cs

# Redis dangerous-command block
grep -n -A7 "CommandMap.Create" src/Sentinel.Redis/RedisConnectionProvider.cs

# Nonce atomicity (Lua CAS-delete)
grep -n -A7 "ConsumeNonceScript" src/Sentinel.Redis/Stores/RedisDpopNonceStore.cs | head -12

# CI gates
grep -n "Gate [0-9]" .github/workflows/security-pipeline.yml
```

Each command prints the exact source lines backing the corresponding claim in this suite.
