# 05 — Configuration Reference

> Every key below is traced to an options class (with its `SectionName` constant), a binding call site, or a shipped `appsettings*.json`. Environment-variable mapping follows standard .NET configuration (`Section:Key` → `Section__Key`; arrays via `__0`, `__1` — used verbatim in `infra/helm/sentinel/values.yaml`: `DPoP__AllowedAlgorithms__0`).

## 1. Configuration Surface Map

| Section | Options type | Bound by | Purpose |
|---|---|---|---|
| `DPoP` | `DPoPOptions` | `AddDPoPValidation()` (`BindConfiguration` + validators + `ValidateOnStart`) | RFC 9449 proof validation policy |
| `AcrRanking` | `AcrRankingOptions` | `ConfigureAcrRanking()` / `AddApplicationLayer()` | ACR → rank table |
| `Sentinel:SecurityLevels` | `SecurityLevelOptions` | `ApplicationServiceCollectionExtensions` | Required ACR + clearance levels |
| `Sentinel:Mtls` | `MtlsBindingOptions` | `AddMtlsBinding()` | RFC 8705 binding, proxy trust |
| `Sentinel:Redis` | `RedisOptions` | `AddRedisSecurityCaches(section)` | Redis/Sentinel-HA connection |
| `Keycloak` | `KeycloakOptions` | `KeycloakServiceExtensions.Configure<KeycloakOptions>` | Authority, audience, session TTL |
| `Sentinel:Keycloak` | `KeycloakOptions` (+ `KeycloakClientOptions` for admin) | `AddKeycloakIntegration(section)` (`BindConfiguration`) | Module-scoped Keycloak config |
| `Cryptography` | `CryptographyOptions` | `SentinelModuleBuilderExtensions` (`BindConfiguration`, hot-reload via `IOptionsMonitor`) | AES-GCM envelope key ring |
| `Ssf` | `SsfOptions` | Host responsibility; consumed via `IOptionsMonitor<SsfOptions>` in `SsfEndpoints` | SSF endpoint flag + webhook auth |
| `Sentinel:Ssf` | `SsfProcessingOptions` | `AddSsfProcessing(configuration)` | SET processing bounds |
| `SdJwt` | `SdJwtOptions` | Host responsibility (constant declared) | SD-JWT feature flag |
| `SessionManagement` | `SessionManagementOptions` | `AddSentinelSessionManagement(configure)` + startup validator | Session lifetime policy |
| `SessionBlacklist` | `SessionBlacklistOptions` | Host responsibility (constant declared) | Blacklist key prefix/TTL |
| `Sentinel:Security:PasswordPolicy` | `PasswordPolicyOptions` | `SecurityControlsServiceCollectionExtensions` | Password strength |
| `Sentinel:Security:Captcha` | `CaptchaOptions` | `SecurityControlsServiceCollectionExtensions` (`.Bind` + annotations) | Turnstile captcha |
| `Sentinel:Rar` | `RarValidationOptions` | `AddRarValidation(configuration)` | RAR matcher policy |
| `SocialFederation` | `SocialFederationOptions` | `KeycloakModuleBuilderExtensions` | Social IdP federation |
| `Registration` | `RegistrationOptions` | `SentinelModuleBuilderExtensions` | Email verification base URL |
| `Kestrel:CertificateReloader` | `KestrelCertificateReloaderOptions` | `AddKestrelCertificateReloader(configuration)` (activated only when `:Path` exists) | TLS cert hot-reload |
| `FeatureFlags:Auth` | raw `IConfiguration` reads | `TokenValidationService` (`JtiReplayEnforcement`), host (`DpopFlow`) | Feature toggles |
| `Security` | raw reads | Sample host | `TrustedRootCaPath`, `TestPublicKey`, `ExpectedDevCertificateThumbprint` |
| `Cors:AllowedOrigins` | raw read | Sample host | CORS allow-list |
| `ConnectionStrings:Redis` / `ConnectionStrings:Postgres` | raw | Host/compose/k8s | Backend endpoints |

## 2. Section-by-Section Reference

### 2.1 `DPoP` (`DPoPOptions`)

| Key | Type | Default | Validation | Semantics |
|---|---|---|---|---|
| `AllowedClockSkewSeconds` | int | `10` | `[Range(0,300)]` | Symmetric skew for `iat` window (doc: "Strictly set to 10 seconds default per FAPI 2.0") |
| `ProofLifetimeSeconds` | int | `60` | `[Range(1,300)]` | Max proof age; also drives replay-cache TTL (`iat + lifetime + skew`) |
| `RequireNonce` | bool | `false` | — | `true` ⇒ every proof must carry the current server nonce (401 `use_dpop_nonce` otherwise) |
| `AllowedAlgorithms` | string[] | `["PS256","ES256"]` | non-empty; ⊆ `{PS256, ES256, EdDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87}`; deduplicated (Ordinal) in `PostConfigure`; `ValidateOnStart` | JWS algorithms accepted for proofs |

Shipped examples: sample host sets `["PS256","ES256","EdDSA","ML-DSA-65"]`; Helm prod pins `PS256`+`ES256` via env.

### 2.2 `AcrRanking` (`AcrRankingOptions`)

| Key | Type | Default | Validation |
|---|---|---|---|
| `Rankings` | `Dictionary<string,int>` (OrdinalIgnoreCase) | `{acr1:1, acr2:2, acr3:3}` | `[Required]`; `Validate()` rejects empty map and **duplicate rank values** |

Consumers: `AcrAuthorizationHandler` (user rank ≥ required rank), `AcrStepUpAuthorizationFilter` (exact match + `auth_time` recency), `StepUpAuthorizationResultHandler`. Example override: `publish-output/appsettings.AcrRanking.example.jsonc` (aal-style mappings supported per the options doc-comment, e.g. `{ "aal1": 1, "aal3": 3 }`).

### 2.3 `Sentinel:Mtls` (`MtlsBindingOptions`)

| Key | Type | Default | Notes |
|---|---|---|---|
| `AllowDirectConnection` | bool | `false` | Allow Kestrel-terminated client certs (no proxy). Sample dev config sets `true` |
| `ValidateChain` | bool | `true` | X509Chain build with clientAuth EKU; doc: "Should always be true in production. Disabled in test environments because test certificates lack a real trust chain." |
| `CertificateHeaders` | string[] | `["X-Client-Cert","X-SSL-Client-Cert","X-ARR-ClientCert","X-Amzn-Mtls-Client-Cert"]` | Priority list for cloud-proxy forwarded certs |
| `TrustedProxies` | string[] | `["127.0.0.1/32","::1/128"]` | `[Required]`; CIDR list; also seeds `ForwardedHeadersOptions.KnownIPNetworks` in the sample host |

### 2.4 `Sentinel:Redis` (`RedisOptions`)

| Key | Type | Default | Notes |
|---|---|---|---|
| `EndPoint` | string? | — (required by validator) | Standalone `"redis-master:6379"` or Sentinel list `"sentinel-0:26379,sentinel-1:26379,sentinel-2:26379"`; validator rejects `://`, control chars, whitespace, `*` |
| `ServiceName` | string? | `null` | Non-empty ⇒ Redis Sentinel HA mode (master discovery/failover) |
| `UseSsl` | bool | `false` | TLS to Redis |
| `Password` | string? | `null` | `[JsonIgnore]`; supply via secret store/env |
| `SyncTimeout` | int | `3000` ms | must be > 0 |
| `ConnectTimeout` | int | `5000` ms | must be > 0 |
| `KeyPrefix` | string | `"sentinel:"` | Environment isolation prefix (prod Helm: `sentinel_prod:`) |

Key space produced (§ prefix + store pattern): `{p}jti:{jti}`, `{p}nonce:{thumbprint}`, `{p}session:{sid}`; idempotency keys are passed through fully formed (`idempotency:{sub}:{uuid}`).

### 2.5 `Keycloak` / `Sentinel:Keycloak` (`KeycloakOptions`, `KeycloakAdminOptions`, `KeycloakClientOptions`)

| Key | Type | Default | Notes |
|---|---|---|---|
| `Authority` | string | — | `[Required][Url]`; realm URL, e.g. `https://localhost:8443/realms/sentinel` |
| `Audience` | string | — | `[Required]`; expected `aud` (`sentinel-api` in shipped configs) |
| `RequireHttpsMetadata` | bool | `true` | Only `"false"` (string-compare) disables; Development-only per README |
| `SsoSessionMaxLifespanSeconds` | int | `28800` (8 h) | Drives `ResolveSessionBlacklistTtl()` for logout/backchannel blacklist TTLs |
| `Admin:ClientId` / `Admin:ClientSecret` / `Admin:Scope` | string | `""`/`""`/`null` | Service-account credentials for the Admin REST client (`KeycloakAdminTokenProvider`) |

`KeycloakClientOptions` (admin HTTP client): `ServerUri`, `Realm`, `ClientId`, `ClientSecret`, `AllowedClockSkewSeconds=60`, `MetadataCacheDurationSeconds=3600`, `HttpTimeoutMs=5000`.

### 2.6 `Cryptography` (`CryptographyOptions`)

| Key | Type | Default | Notes |
|---|---|---|---|
| `ActiveKeyId` | string | `""` | Key used for new envelopes; must exist in `KeyRing` |
| `KeyRing` | `Dictionary<string,string>` | `{}` | keyId → base64 32-byte AES-256 key (setter required: "init-only setters are silently skipped by the NativeAOT configuration binder") |
| `LegacyMasterKey` | string? | `null` | Decrypts pre-versioning V0 ciphertexts |

Hot-reloadable (`IOptionsMonitor.OnChange` → volatile state swap). Reference: `publish-output/appsettings.Cryptography.example.jsonc`. **Never ship the placeholder key** `AAAA…=` present in `publish-output/appsettings.json`/`appsettings.Development.json` — it is a 32-byte all-zero key for local bootstrapping only.

### 2.7 `Ssf` (`SsfOptions`) and `Sentinel:Ssf` (`SsfProcessingOptions`)

| Key | Default | Consumer |
|---|---|---|
| `Ssf:Enabled` | `true` | `SsfEndpoints` (false ⇒ 404 route obfuscation) |
| `Ssf:AllowedClockSkewSeconds` | `300` | declared for SET timestamp validation |
| `Ssf:SetTokenLifetimeSeconds` | `3600` | declared SET lifetime bound |
| `Ssf:RequireAuthToken` | `false` | enables `SSF-Auth-Token` check |
| `Ssf:AuthToken` | `null` | shared webhook secret (constant-time compare) |
| `Sentinel:Ssf:SessionRevocationTtlSeconds` | `28800` | blacklist TTL applied by `SsfEventProcessor` |
| `Sentinel:Ssf:MaxEventAgeSeconds` | `300` | SET `iat` max age |
| `Sentinel:Ssf:AllowedClockSkewSeconds` | `300` | temporal-bound skew |

### 2.8 `SessionManagement` (`SessionManagementOptions`)

| Key | Default | Validation |
|---|---|---|
| `RequireDpopBinding` | `true` | — |
| `SessionMaxLifetime` | `08:00:00` | must be > 0 (startup validator) |
| `BlacklistCleanupInterval` | `01:00:00` | must be > 0 (startup validator) |

### 2.9 `SessionBlacklist` (`SessionBlacklistOptions`)

| Key | Default |
|---|---|
| `KeyPrefix` | `"blacklist:sid:"` |
| `DefaultTtlSeconds` | `3600` ("Typically set to the max token lifetime + grace period") |

### 2.10 `SdJwt` (`SdJwtOptions`) and `SdJwtVerificationOptions` (code-registered)

| Key | Default | Notes |
|---|---|---|
| `SdJwt:Enabled` | `true` | feature flag |
| `SdJwt:RequireKeyBindingNonce` | `false` | sample host registers `SdJwtVerificationOptions` explicitly |
| `SdJwtVerificationOptions.KeyBindingMaxAgeSeconds` | `60` (sample host sets `300`) | KB-JWT freshness |
| `SdJwtVerificationOptions.RequireKeyBindingNonce` | `true` (secure-by-default; sample host sets `false`) | KB nonce enforcement |
| `SdJwtVerificationOptions.AllowedClockSkewSeconds` | `0` (sample host sets `60`) | strict by default |
| `SdJwtVerificationOptions.AllowedDisclosureHashAlgorithms` | `["sha-256"]` | RFC 9901 per source annotation |

### 2.11 `Sentinel:Security:PasswordPolicy` (`PasswordPolicyOptions`)

| Key | Default | Sample host override |
|---|---|---|
| `MinimumLength` | `12` | 12 |
| `MaximumLength` | `128` | 128 |
| `RequireUppercase` / `RequireLowercase` / `RequireDigit` / `RequireNonAlphanumeric` | `true` ×4 | same |
| `MinimumEntropyBits` | `60.0` | `50.0` |
| `CustomBlacklist` | `[]` | `[]` |

Enforced by `EnterprisePasswordStrengthValidator` (character-class checks + entropy estimate; property-based tests in `PasswordStrengthPropertyTests`).

### 2.12 `Sentinel:Security:Captcha` (`CaptchaOptions`)

| Key | Default | Validation |
|---|---|---|
| `Enabled` | `true` | — |
| `SecretKey` | `""` | `[Required]` |
| `VerificationUrl` | `https://challenges.cloudflare.com/turnstile/v0/siteverify` | `[Required]`, absolute URI |
| `TimeoutSeconds` | `5` | `[Range(1,30)]` |

`CloudflareTurnstileCaptchaService` posts siteverify over the TLS-hardened handler (TLS enforcement tested by `CaptchaTlsEnforcementTests`).

### 2.13 `Sentinel:SecurityLevels` (`SecurityLevelOptions`)

| Key | Default | Shipped values |
|---|---|---|
| `RequiredAcr` | `"acr3"` | prod `acr3`, dev/sample `acr2` |
| `ElevatedClearanceLevels` | `["top-secret","classified"]` | dev adds `"secret"` |

### 2.14 `Sentinel:Rar` (`RarValidationOptions`)

| Key | Default |
|---|---|
| `MonetaryPrecisionTolerance` | `0.0001m` |
| `CaseSensitiveComparison` | `false` |
| `RequireExactMatch` | `false` |
| `MaxAuthorizationDetailsCount` | `100` |

### 2.15 `Kestrel:CertificateReloader` (`KestrelCertificateReloaderOptions`)

| Key | Default | Notes |
|---|---|---|
| `Path` | `null` | PEM (cert+key) or PFX; presence of this key activates the reloader in the sample host |
| `Password` | `null` | PFX only |
| `DebounceInterval` | `500 ms` | guards partial writes |
| `WarningDaysThreshold` | `30` days | near-expiry alerting via `crypto.tls.cert_days_remaining` |
| `StartupTimeout` | `30 s` | initial load budget |

### 2.16 Feature flags & host-level keys

| Key | Shipped value | Effect |
|---|---|---|
| `FeatureFlags:Auth:DpopFlow` | `true` (all shipped appsettings) | DPoP flow toggle placeholder (README configuration table) |
| `FeatureFlags:Auth:JtiReplayEnforcement` | Helm prod env `"true"` | Activates access-token `jti` single-use enforcement in `TokenValidationService` |
| `Security:TrustedRootCaPath` | `infra/certs/ca.crt` (sample), `/var/run/sentinel/ca/ca.crt` (compose/k8s) | Custom root trust for Keycloak backchannel |
| `Security:TestPublicKey` | dev/test only | Bypasses JWKS discovery with a pinned SPKI ECDSA key (acceptance tests) |
| `Security:ExpectedDevCertificateThumbprint` | dev only | Thumbprint pinning fallback when no CA path |
| `Cors:AllowedOrigins` | `[]` | When non-empty enables CORS with methods `GET/POST/PUT/PATCH/DELETE`, headers `Authorization, DPoP, Content-Type, Idempotency-Key, SSF-Auth-Token`, exposed `DPoP-Nonce, WWW-Authenticate` |
| `ConnectionStrings:Redis` | `localhost:6379` | README minimum-required key |
| `AllowedHosts` | `*` (publish-output/appsettings.json) | Host filtering |
| `Logging:LogLevel` | `Default: Information`, `Microsoft.AspNetCore: Warning` | shipped defaults |

### 2.17 Environment variables (container/K8s)

Verified in `docker-compose.yml`, `infra/k8s/sentinel-api-deployment.yaml`, Helm `values.yaml`, Dockerfile:

```bash
ASPNETCORE_ENVIRONMENT=Production
ASPNETCORE_URLS=https://+:8080                       # k8s manifest (container: http://+:8080)
ASPNETCORE_Kestrel__Certificates__Default__Path=/var/run/sentinel/tls/tls.crt
ASPNETCORE_Kestrel__Certificates__Default__KeyPath=/var/run/sentinel/tls/tls.key
DOTNET_EnableDiagnostics=0                           # disables diagnostics IPC in production images
DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.observability.svc.cluster.local:4317
OTEL_SERVICE_NAME=sentinel-api
ConnectionStrings__Redis / ConnectionStrings__Postgres        # secretKeyRef: sentinel-runtime-secrets
Keycloak__Authority / Keycloak__Audience / Keycloak__RequireHttpsMetadata
Sentinel__Keycloak__Authority / __Audience / __RequireHttpsMetadata / __ClientSecret
Sentinel__Redis__EndPoint=redis:6379
Sentinel__Redis__EnableInMemoryFallback=false        # compose: explicit fail-closed
Security__TrustedRootCaPath=/var/run/sentinel/ca/ca.crt
FeatureFlags__Auth__JtiReplayEnforcement=true
DPoP__AllowedAlgorithms__0=PS256
DPoP__AllowedAlgorithms__1=ES256
```

## 3. Startup Validation & Production Guardrails (summary)

| Guard | Trigger | Effect |
|---|---|---|
| DPoP algorithm allow-list validator | configured alg ∉ global set or list empty | host fails to start (`ValidateOnStart`) |
| `DpopProofValidator` ctor invariant | same, at resolution | `CryptographicException` |
| `RedisOptionsValidator` | endpoint/prefix/timeouts malformed | options validation failure; in non-Dev, `SecurityInvariantsStartupFilter` escalates to `InvalidOperationException` |
| `SecurityInvariantsStartupFilter` (non-Development) | `InMemoryIdempotencyStore` registered/absent; EF-backed `IDpopNonceStore`/`IJtiReplayCache` | **process refuses to start** with "CRITICAL SECURITY INVARIANT VIOLATED" messages |
| `SessionManagementOptionsValidator` | non-positive lifetimes | fail-fast |
| `AcrRankingOptions.Validate` | empty/duplicate ranks | `InvalidOperationException` |
| Captcha/PasswordPolicy data annotations | missing `[Required]`, range violations | options validation failure |

## 4. Reference `appsettings.json` (published host baseline)

`publish-output/appsettings.json` (production-shaped) — reproduced verbatim:

```json
{
  "ConnectionStrings": { "Redis": "localhost:6379" },
  "AcrRanking": { "Rankings": { "acr1": 1, "acr2": 2, "acr3": 3 } },
  "Sentinel": {
    "SecurityLevels": { "RequiredAcr": "acr3", "ElevatedClearanceLevels": [ "top-secret", "classified" ] },
    "Keycloak": {
      "Authority": "https://localhost:8443/realms/sentinel",
      "Audience": "sentinel-api",
      "SsoSessionMaxLifespanSeconds": 28800
    }
  },
  "Keycloak": {
    "Authority": "https://localhost:8443/realms/sentinel",
    "Audience": "sentinel-api",
    "SsoSessionMaxLifespanSeconds": 28800
  },
  "Cryptography": { "ActiveKeyId": "default", "KeyRing": { "default": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" } },
  "FeatureFlags": { "Auth": { "DpopFlow": true } },
  "Logging": { "LogLevel": { "Default": "Information", "Microsoft.AspNetCore": "Warning" } },
  "AllowedHosts": "*"
}
```

Development delta (`publish-output/appsettings.Development.json`): `RequiredAcr` → `acr2`, authority → `http://localhost:8080/realms/sentinel`, `RequireHttpsMetadata: false`, extra clearance level `"secret"`.

**Production checklist derived from the guards above**: replace the zero key in `Cryptography:KeyRing` (or source it from Vault — `VaultPrivacyHardeningExtensions`); set `DPoP:AllowedAlgorithms` explicitly; keep `Keycloak:RequireHttpsMetadata=true`; provide `Sentinel:Redis` with a Redis (not EF) store set; set `FeatureFlags:Auth:JtiReplayEnforcement=true`; configure `Sentinel:Mtls:TrustedProxies` to the real ingress CIDRs; supply `Idempotency-Key`-capable Redis store (otherwise startup is blocked).
