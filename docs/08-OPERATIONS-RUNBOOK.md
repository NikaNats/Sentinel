# 08 — Operations Runbook

> Sources: `src/Sentinel.Security.Diagnostics/AuthTelemetry.cs` (metric catalog), source-wide `LoggerMessage.Define` declarations (event catalog), `infra/monitoring/sre-alerts.yaml` + `infra/observability/prometheus/alerts.yml` (alert rules), `docs/SRE_SOC_RUNBOOKS.md` / `docs/CRYPTO_LIFECYCLE_RUNBOOK.md` (repository runbooks), middleware/store code for failure semantics. Prometheus metric names are the OTel-derived forms (`.` → `_`, counters suffixed `_total`) exactly as documented in the header comment of `infra/monitoring/sre-alerts.yaml`.

## 1. Telemetry Contract

- Meter: **`Sentinel.Auth.Metrics`**; ActivitySource: **`Sentinel.Auth.Tracing`** (`AuthTelemetry.SourceName`/`MeterName`). Both must be registered at host startup (`AddMeter(AuthTelemetry.MeterName)`, `AddSource(AuthTelemetry.SourceName)` — done in the reference host); the OTel SDK hosted service flushes on SIGTERM so "final seconds" security events are not lost (`AuthTelemetry` lifecycle comment).
- Export paths: Prometheus scrape at `/metrics` (`MapPrometheusScrapingEndpoint`) and/or OTLP to the collector (traces `otlp/tempo`, metrics Prometheus exporter, logs `otlphttp/loki`), per `infra/observability/collector/config.yaml`.

### 1.1 Metric catalog (exact names, units, semantics — all from `AuthTelemetry.cs`)

| Metric (code name) | Prometheus form | Type / unit | Emitted when |
|---|---|---|---|
| `auth.dpop.failures` (tag `reason`) | `auth_dpop_failures_total{reason}` | Counter | Every DPoP failure; reasons include `missing_dpop_proof`, `malformed_dpop_proof`, `l1_anti_flood_blocked`, `invalid_signature`, validator error codes, `infrastructure_unavailable` |
| `auth.jti.replays_total` | `auth_jti_replays_total` | Counter | Access-token jti replay detected (`SecurityEventEmitter.EmitTokenReplay` path) |
| `auth.token.issued` | `auth_token_issued_total` | Counter | Tokens issued, by assurance level |
| `auth.token.validation.duration` | `auth_token_validation_duration_seconds_bucket` (histogram, **unit `s`**) | Histogram | DPoP middleware records elapsed validation seconds per request |
| `auth.redis.degraded_mode_activations` | `auth_redis_degraded_mode_activations_total` | Counter | Transitions into node-local replay protection (Redis degradation) |
| `auth.dpop.nonce_mismatch_total` | `auth_dpop_nonce_mismatch_total` | Counter | Nonce mismatch / stale presentation / failed atomic compare-delete |
| `auth.idempotency.lock_contention_total` | `auth_idempotency_lock_contention_total` | Counter | Idempotency SET NX collisions/retries under concurrency |
| `crypto.jwks.refresh_total` | `crypto_jwks_refresh_total` | Counter | JWKS refresh requested after kid-miss |
| `crypto.jwks.kid_miss_total` (tag `kid`) | `crypto_jwks_kid_miss_total{kid}` | Counter | Signing-key lookup miss during JWT validation |
| `crypto.tls.cert_days_remaining` | `crypto_tls_cert_days_remaining` (gauge, unit `days`) | Observable gauge | Updated by `KestrelCertificateReloader` on every (re)load |
| `crypto.lazy_rewraps_total` (tag `key_id`) | `crypto_lazy_rewraps_total{key_id}` | Counter | Envelope ciphertexts re-encrypted under the active key during decryption |
| `crypto.keyring.active_key_mismatch` (tag `key_id`) | `crypto_keyring_active_key_mismatch{key_id}` | Counter | Decryption performed with a non-active keyring key (rotation-drift signal) |
| `auth.keycloak.revocation_failures` | `auth_keycloak_revocation_failures_total` | Counter | Created ad-hoc in `AuthEndpoints.LogoutAsync` when Keycloak session revocation returns false |

### 1.2 Log event-ID catalog (compiled `LoggerMessage` delegates)

| Component | EventId / Name | Level | Meaning |
|---|---|---|---|
| `DpopValidationMiddleware` | 2001 `DpopSignatureError` | Warning | Rejected unsupported algorithm / signature problem |
| | 2002 `DpopAttackBlocked` | **Critical** | "SECURITY ALERT": oct-key confusion or private key material in public JWK |
| | 2003 `DpopInfrastructureUnavailable` | Error | Store outage → failing closed with HTTP 503 |
| `MtlsBindingMiddleware` | 3001 `MtlsWarning` | Warning | DPoP-bound without proof / missing `cnf` claim / chain failures |
| | 3002 `MtlsProxyError` | Warning | Cert missing/mismatched, includes RemoteIP |
| | 3003 `MtlsCryptoError` | Error | Malformed certificate (Cryptographic/Format exception) |
| `TokenValidationService` | 3001 `TokenValidationWarning` | Warning | exp missing/invalid, jti missing |
| | 3002 `TokenRevocationAlert` | **Critical** | Subject revoked / replay detected / session blacklisted |
| | 3003 `TokenValidationCriticalFailure` | Error | Fail-closed triggered by store unavailability |
| `MlDsaSignatureVerifier` | 4001 `MlDsaMissingAlgorithm` | Warning | Null/empty algorithm |
| | 4002 `MlDsaPlatformUnsupported` | **Critical** | Host OS lacks native FIPS 204 support — failing closed |
| | 4003 `MlDsaUnsupportedAlgorithm` | Warning | Unknown ML-DSA identifier |
| | 4005 `MlDsaVerificationSuccess` | Debug | Verified |
| | 4006 `MlDsaVerificationFailed` | Warning | "Possible payload alteration or signature forgery detected." |
| | 4007 `MlDsaCryptoError` | Error | Native crypto platform error |
| | 4008 `MlDsaArgumentError` | Error | Invalid state/argument in verifier core |

Structured SIEM markers used in log messages: `security:fips_mode_enabled`, `security:ssf_auth_failed`, `RAR_VALIDATION_FAILED`, plus `SecurityEventEmitter` events (`EmitTokenReplay`, `EmitDpopValidationFailure`, `EmitSessionRevoked`, `EmitConfigurationChange`) with privacy-hashed identifiers and correlation IDs (`X-Correlation-ID` baggage) for pivoting.

## 2. Alert Rules (as shipped)

### 2.1 Production SRE rules — `infra/monitoring/sre-alerts.yaml`

| Alert | Expression (verbatim) | For | Severity |
|---|---|---|---|
| `NativeAotMemoryLeakDetected` | `deriv(container_memory_working_set_bytes{container="sentinel-api"}[6h]) > 0 and predict_linear(container_memory_working_set_bytes{container="sentinel-api"}[1h], 86400) > container_spec_memory_limit_bytes{container="sentinel-api"}` | 30m | critical |
| `SocketExhaustionImminent` | `sum(node_sockstat_TCP_tw) > 20000 or sum(rate(node_netstat_Tcp_PassiveOpens[5m])) > 5000` | 2m | warning |
| `RedisDegradedModeActivated` | `increase(auth_redis_degraded_mode_activations_total[2m]) > 0` | 30s | critical |
| `LatencySlaBreached` | `histogram_quantile(0.99, sum(rate(auth_token_validation_duration_seconds_bucket[2m])) by (le)) > 0.050` (p99 token-validation > 50 ms) | 1m | critical |
| `DpopFailureSurge` | `sum(increase(auth_dpop_failures_total[5m])) > 1000` | 2m | warning |

### 2.2 Gate rules — `infra/observability/prometheus/alerts.yml` (Layer-2 observability gate)

`HighDPoPFailures` (`increase(auth_dpop_failures_total[1m]) > 0`, warning) and `TokenReplayDetected` (`increase(auth_jti_replays_total[1m]) > 0`, **critical**) intentionally fire at > 0 to prove the signal path end-to-end; the file header states production baselining is an operator decision (use §2.1 rules in prod).

## 3. Fail-Closed Behavior — Operator Decision Table

The system **never** silently degrades security checks. Expected client-visible behavior and operator response:

| Symptom | Root cause class | Client sees | Operator action |
|---|---|---|---|
| 503 + `Retry-After: 5`, problem `/errors/service-unavailable`, log 2003 | Redis/nonce/replay store outage during DPoP validation | Retryable error | Check Redis (Sentinel failover status if HA), network policy, `auth_redis_degraded_mode_activations_total`; scale/restore Redis. **Do not** switch to in-memory stores — startup filter blocks them outside Development by design |
| 401 `/errors/unauthorized` spike + `TokenValidationCriticalFailure` (3003) | Session blacklist store outage | Re-auth loops | Same as above; verify `HybridSessionBlacklistCache` L2/L3 health (Postgres reachable) |
| 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"` en masse, `auth_dpop_nonce_mismatch_total` rising | Clients ignoring `DPoP-Nonce` rotation, or Redis key-prefix collision between environments | Clients fail until they fix nonce handling | Confirm prefix isolation (`sentinel_prod:` vs `staging:`), inspect client SDK behavior |
| `auth_jti_replays_total` > 0 (`TokenReplayDetected`) | Token theft/replay attempt **or** client retrying a consumed single-use token | 401 | Triage via `SecurityEventEmitter` replay events (hashed jti/sub/IP + correlation id); if theft suspected, trigger subject revocation (`POST /auth/logout-all` equivalent via Keycloak admin) |
| `crypto_jwks_kid_miss_total{kid}` spikes | Keycloak signing-key rotation ahead of client cache | Transient 401s | Usually self-heals (JWKS refresh counter rises); if persistent, check Keycloak realm key status |
| `crypto_tls_cert_days_remaining` < 30 (`WarningDaysThreshold`) | Certificate expiry approaching | — | Renew cert; hot-reload picks it up without restart (`KestrelCertificateReloader`), gauge updates on reload |
| `crypto_keyring_active_key_mismatch` sustained | Key-ring rotated without updating `ActiveKeyId`, or legacy data | — | Follow §4 rotation runbook |
| Process refuses to start: "CRITICAL SECURITY INVARIANT VIOLATED…" | Production config drift (in-memory idempotency store / EF-backed nonce or jti stores) | Deploy blocked | Fix DI registrations to Redis-backed stores; this guard is intentional (`SecurityInvariantsStartupFilter`) |
| ML-DSA critical log 4002 | Host OS lacks native FIPS 204 support | PQC proofs rejected (fail-closed) | Move workloads to a platform where `MLDsa.IsSupported` is true, or remove `ML-DSA-*` from `DPoP:AllowedAlgorithms` until then |

## 4. Cryptographic Key-Rotation Runbooks

### 4.1 Envelope data key (`Cryptography:KeyRing`) — zero-downtime

Per `AesGcmEncryptionService` mechanics and `docs/CRYPTO_LIFECYCLE_RUNBOOK.md`:

```text
1. Generate a new 32-byte key:  openssl rand -base64 32
2. Add it to the ring under a new id (e.g. "2026-09-rev1") and set ActiveKeyId to it.
   Update via the config store consumed by IOptionsMonitor<CryptographyOptions>
   (K8s: update the secret/configmap; the service rebuilds state OnChange — no restart).
3. Monitor: crypto_lazy_rewraps_total should climb as old ciphertexts are read;
   crypto_keyring_active_key_mismatch should decay to zero as the ring converges.
4. After all V0/legacy reads cease (no LegacyMasterKey hits in logs), remove
   LegacyMasterKey; after the old key stops appearing in mismatch metrics, retire it
   from the ring per retention policy (NIST SP 800-57 key lifecycle, per options doc-comment).
```

### 4.2 TLS serving certificate

1. Replace the file at `Kestrel:CertificateReloader:Path` (atomic write recommended; the watcher debounces 500 ms against partial writes).
2. `KestrelCertificateReloader` swaps the certificate via Kestrel's `ServerCertificateSelector` without restart; `CertificateReloaded` event fires; `crypto.tls.cert_days_remaining` updates.
3. Verify: `curl -vk https://host:8080/healthz 2>&1 | grep -i "notAfter"` and the gauge value.

### 4.3 Keycloak signing keys (JWKS)

Rotation is IdP-side; Sentinel reacts via kid-miss → JWKS refresh (`crypto.jwks.refresh_total`). E2E proof: `JwksRotationIntegrationTests` with `RotatingJwksServer` (CI Gate 10). Operator steps: rotate in Keycloak, watch kid-miss/refresh counters return to baseline; no API restart needed.

## 5. Routine Operations

| Task | Command / locus |
|---|---|
| Health | `GET /healthz` (anonymous; also the k8s probe target) |
| Metrics | `GET /metrics` (Prometheus text format) |
| API docs (Development only, Scalar) | `GET /docs` (dev CSP relaxes only for `/scalar`/docs paths under Development) |
| Redis smoke | `redis-cli -h redis ping` (compose); app-level: watch `auth_redis_degraded_mode_activations_total` |
| Fail-closed drill | `bash tests/scripts/validate-fail-closed.sh` |
| Observability drill | `bash tests/scripts/validate-observability.sh` |
| TLS posture audit | `bash tests/infrastructure-tls-audit.sh` |
| OpenAPI drift audit | `bash tests/infrastructure-openapi-audit.sh` |
| DPoP E2E dance (in-cluster) | `dpop-dance.sh` / `dpop-e2e.sh` (Node-based proof signing against the running stack) |
| Session blacklist GC | Automatic: Redis TTL; EF path swept by `SecurityCacheCleanupService` every 15 minutes |
| Scale | HPA 2→6 replicas (CPU 70% / memory 80% targets); PDB `minAvailable: 1` |
| Incident procedures & escalation | `docs/SRE_SOC_RUNBOOKS.md` (monitoring, IR procedures, troubleshooting guides, maintenance checklists with bash/PowerShell commands) |

## 6. On-Call Quick Reference

**Service identity**: `OTEL_SERVICE_NAME=sentinel-api`; traces under `Sentinel.Auth.Tracing`; every response carries `X-Correlation-ID` — capture it first in any incident ticket; DPoP-bound requests additionally carry baggage `dpop.jkt` (privacy-hashed where logged).

**First-five-minutes checklist for a security alert**:

1. Classify by metric: replay (`auth_jti_replays_total`) vs DPoP failures (`auth_dpop_failures_total{reason}`) vs infra (`auth_redis_degraded_mode_activations_total`, 503s).
2. Pull correlated logs by event IDs (§1.2) — Critical events 2002/3002/4002 are page-worthy.
3. Check `reason` tag distribution: `l1_anti_flood_blocked` surge ⇒ flood/credential-stuffing attempt against a thumbprint; `invalid_signature` surge ⇒ client misconfiguration or attack; `infrastructure_unavailable` ⇒ store outage.
4. Verify no environment mixing: Redis `KeyPrefix`, `TrustedProxies` CIDRs, `RequireHttpsMetadata`.
5. If theft confirmed: revoke subject sessions (logout-all path → Keycloak admin `POST users/{sub}/logout`), blacklist persists automatically for `SsoSessionMaxLifespanSeconds`.

**Known-benign signals**: 401 `use_dpop_nonce` on a client's *first* request per thumbprint (challenge–response is by design); `DPoP-Nonce` rotation headers on every success; 200 responses from `/auth/backchannel-logout` even for invalid tokens (deliberate RFC-mandated non-disclosure).
