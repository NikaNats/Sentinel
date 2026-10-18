# Enterprise Cryptographic & PKI Lifecycle Runbook

**Document ID:** CRYPTO-0001  
> **Status**: DOCUMENTATION REVIEW / APPROVED PROCEDURE (execution evidence is separate)
**Scope:** Sentinel core libraries, ASP.NET Core middleware, and reference sample  
**Compliance Baseline:** FAPI 2.0 Baseline/Advanced · NIST 800-57 · FedRAMP High · GDPR · FIPS 204 (ML-DSA)

---

## 1. Overview

This runbook operationalizes the **Enterprise Cryptographic & PKI Lifecycle Architecture (2026)** across four pillars:

| Pillar | Capability | Key Metrics |
|--------|------------|-------------|
| **1. JWKS Key Rotation** | Kid-miss telemetry + configuration-manager behavior requires host/live verification | `crypto.jwks.refresh_total`, `crypto.jwks.kid_miss_total` |
| **2. TLS Cert Reload** | Kestrel `ServerCertificateSelector` + initial/options-change paths; inspected watcher disabled | `crypto.tls.cert_days_remaining` |
| **3. mTLS Cert Cache** | Raw-PEM SHA-256 keying + sliding expiration | Bounded by `MtlsCertificateCache` size limit |
| **4. Envelope Rewrap** | `IEnvelopeEncryptionService.DecryptEnvelope` → lazy re-wrap | `crypto.lazy_rewraps_total`, `crypto.keyring.active_key_mismatch` |

All metrics are emitted via `Sentinel.Security.Diagnostics.AuthTelemetry` (meter `Sentinel.Auth.Metrics`).

---

## 2. Pillar 1 — JWKS Key Rotation

### 2.1 Architecture

- **Mock/Production JWKS Server** serves `/.well-known/jwks.json` + OIDC discovery.
- **JWT Bearer** configured with `MetadataAddress` + `Authority` pointing to JWKS server.
- The inspected `KeycloakOptions` does not define `JwksRefreshIntervalSeconds`; no Sentinel configuration value was established for that name. Configuration-manager refresh behavior is host/framework-specific and requires live verification.
- **Grace Period**: Retired keys may remain in JWKS until all in-flight tokens expire; retention is an IdP/operator decision, not proof of a Sentinel refresh callback.

### 2.2 Rotation Procedure (Day 0 → Day 90)

| Day | Action | Verification |
|-----|--------|--------------|
| 0 | Generate new key `key-N+1`, add to JWKS (keep `key-N` active) | Verify the actual configuration-manager behavior; the Sentinel callback counter alone is not proof of refresh |
| 1-7 | Switch active key to `key-N+1` (config `ActiveKeyId`) | New tokens minted with `key-N+1` validate |
| 7-30 | Monitor `crypto.jwks.kid_miss_total` (should be 0) | Alert if > 0 |
| 30-90 | Remove `key-N` from JWKS after token TTL expiry | `crypto.jwks.kid_miss_total` for retired kid = 0 |

### 2.3 Known Limitation

> **JWT Bearer handler with HTTP metadata endpoints** (github.com/dotnet/aspnetcore/issues/28948):  
> The ASP.NET Core JWT Bearer handler's `ConfigurationManager` has known issues fetching JWKS over HTTP.  
> **Mitigation**: Use HTTPS in production (Keycloak TLS). Integration tests document cryptography correctness via direct `JsonWebTokenHandler` validation; handler integration tested separately with HTTPS.

---

## 3. Pillar 2 — TLS Certificate Reload

### 3.1 Configuration

```yaml
Kestrel:
  CertificateReloader:
    Path: "/etc/sentinel/certs/server.pem"  # PEM with cert + private key
    DebounceInterval: "00:00:00.500"       # 500ms debounce
    WarningDaysThreshold: 30                # Alert threshold
```

### 3.2 Reload Procedure

1. Write new PEM to `Path` (atomic write: write to temp + rename).
2. Change the certificate-reloader options/config (or restart); the inspected `FileSystemWatcher` is constructed with `EnableRaisingEvents = false`, so file replacement alone does not establish a watcher-triggered reload.
3. On a successful reload, `AuthTelemetry.TlsCertDaysRemaining` updates and `CertificateReloaded` may fire.
4. In-flight handshakes complete with the old cert; new connections use the newly selected cert after the swap.

### 3.3 Alerting

| Metric | Threshold | Action |
|--------|-----------|--------|
| `crypto.tls.cert_days_remaining` < 30 | Warning | Schedule renewal |
| `crypto.tls.cert_days_remaining` < 7 | Critical | Immediate renewal |

---

## 4. Pillar 3 — mTLS Certificate Cache

### 4.1 Implementation

- **Cache Key**: `mtls:` + SHA-256(UTF8(raw PEM)) — **already implemented**.
- **Sliding Expiration**: 5 minutes (configurable via `MtlsBindingOptions`).
- **Capacity Limit**: 10,000 entries (bounded memory, LRU eviction).

### 4.2 Rotation Behavior

- New client cert → distinct raw PEM → distinct cache key → cache miss → parse → cache.
- Old cert entries expire via sliding window.
- Rotation storm bounded by `SizeLimit` (10k).

---

## 5. Pillar 4 — Envelope Encryption & Lazy Re-wrap

### 5.1 API

```csharp
public interface IEnvelopeEncryptionService : IEncryptionService
{
    EnvelopeDecryptionResult DecryptEnvelope(byte[] cipherData);
}

public sealed record EnvelopeDecryptionResult(
    string PlainText,
    bool RequiresRewrap,
    byte[]? RewrappedCipher);
```

### 5.2 Behavior

| Input Ciphertext | KeyId in Envelope | `RequiresRewrap` | `RewrappedCipher` |
|------------------|-------------------|------------------|-------------------|
| V1 envelope, Active Key | == ActiveKeyId | `false` | `null` |
| V1 envelope, Retired Key | != ActiveKeyId (in KeyRing) | `true` | Re-encrypted with Active Key |
| V0 legacy | N/A (no MagicByte) | `true` | Re-encrypted with Active Key |
| Unknown/invalid versioned envelope | Unrecognized/corrupt ciphertext, malformed header, or authentication failure | N/A | Falls through to legacy handling when `LegacyMasterKey` is configured; otherwise throws through the resulting legacy/no-key path. This is not a distinct unknown-key exception. |

### 5.3 Repository Integration (Sample)

```csharp
var result = envelopeService.DecryptEnvelope(ciphertext);
if (result.RequiresRewrap)
{
    // The caller owns persistence; this code shape is illustrative, not a production caller.
    await repository.UpdateAsync(id, result.RewrappedCipher);
}
```

The inspected production source contains no caller that persists `RewrappedCipher`; `LazyRewraps` and `KeyRingActiveKeyMismatches` count service-side processing, not successful storage convergence.

---

## 6. Metrics & Alerting

| Metric | Type | Labels | Alert Rule |
|--------|------|--------|------------|
| `crypto.jwks.refresh_total` | Counter | — | A nonzero value records a callback attempt; it does not prove refresh success or self-healing |
| `crypto.jwks.kid_miss_total` | Counter | `kid` | Any > 0 → unknown key in traffic |
| `crypto.tls.cert_days_remaining` | ObservableGauge (days) | — | < 30 warn, < 7 critical |
| `crypto.lazy_rewraps_total` | Counter | `key_id` | Rate > baseline → rotation in progress |
| `crypto.keyring.active_key_mismatch` | Counter | `key_id` | Any > 0 → config drift |

All metrics exported via Prometheus `/metrics` endpoint only when the host configures an exporter/endpoint.

---

## 7. CI Gate 10

```yaml
# .github/workflows/security-pipeline.yml (build-scan job)
- name: Gate 10 - Cryptographic Lifecycle & Rotation Tests
  run: |
    dotnet build tests/Sentinel.Tests.Integration/Sentinel.Tests.Integration.csproj \
      --configuration Release --no-restore --nologo \
      -p:SkipGetBuildVersion=true -p:NBGV_Disable=true
    dotnet vstest tests/Sentinel.Tests.Integration/bin/Release/net10.0/Sentinel.Tests.Integration.dll \
      --TestCaseFilter:"FullyQualifiedName~JwksRotation" \
      --logger:"console;verbosity=detailed"
    dotnet build tests/Sentinel.Tests.Unit/Sentinel.Tests.Unit.csproj \
      --configuration Release --no-restore --nologo \
      -p:SkipGetBuildVersion=true -p:NBGV_Disable=true
    dotnet vstest tests/Sentinel.Tests.Unit/bin/Release/net10.0/Sentinel.Tests.Unit.dll \
      --TestCaseFilter:"FullyQualifiedName~MtlsCertificateCache|FullyQualifiedName~AesGcmEncryptionService" \
      --logger:"console;verbosity=detailed"
```

Runs in `build-scan` (no containers required).

---

## 8. Compliance Mapping

| Standard | Control | Evidence |
|----------|---------|----------|
| NIST 800-57 | Key rotation, grace period | Pillar 1 + 4 |
| FedRAMP High | Crypto agility, key mgmt | All pillars + metrics |
| FAPI 2.0 | JWKS rotation, TLS | Pillar 1 + 2 |
| GDPR | Data encryption at rest | Pillar 4 (lazy re-wrap) |

---

## 9. Related Documents

- `COMPLIANCE_AUDIT_MATRIX.md` — Control mapping
- `KEYCLOAK_FAPI_ENFORCEMENT.md` — Keycloak JWKS config
- `OTEL_DOTNET_INTEGRATION_SNIPPET.md` — OpenTelemetry setup