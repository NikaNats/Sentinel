# Implementation Plan: User Authentication & Token Issuance

> **Plan ID**: PLAN-0001  
> **Linked Spec**: SPEC-0001 (APPROVED)  
> **Constitution Ref**: FortressAPI Constitution v2.0.0  
> **Status**: APPROVED

---

## Meta

| Field | Value |
|---|---|
| **Plan ID** | PLAN-0001 |
| **Linked Spec** | SPEC-0001 |
| **Linked Tasks** | TASK-0001 |
| **Tech Lead** | Senior IAM Engineer |
| **Security Reviewer** | Security Working Group |
| **Created** | 2026-03-13 |
| **Target Release** | v1.0.0 |
| **Estimated Effort** | 8 dev-days |

---

## 1. Pre-Implementation Checklist

| Gate | Status |
|---|---|
| SPEC-0001 in APPROVED state | ✅ |
| STRIDE/DREAD complete, all HIGH threats mitigated | ✅ |
| Security reviewer approval | ✅ |
| FIPS 140-3 algorithm set verified | ✅ |
| Keycloak config design reviewed | ✅ |
| All new NuGet packages scanned (zero CRITICAL CVEs) | ✅ |
| Feature flag key defined | ✅ `feature.auth.dpop-flow` |

---

## 2. Architecture Overview

### 2.1 Component Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Government Employee Client                       │
│   Browser / Desktop App                                              │
│   - Generates ephemeral DPoP key pair (EC P-256 in FIPS mode)       │
│   - Holds DPoP private key in memory only — never persisted          │
└────────────────────────┬────────────────────────────────────────────┘
                         │ HTTPS TLS 1.3
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        API Gateway                                   │
│   - TLS termination (TLS 1.3 only)                                  │
│   - Rate limiting (PAR: 10/min/IP, Token: 20/min/IP)                │
│   - mTLS to backend services                                         │
│   - Forwards: Authorization, DPoP headers unchanged                 │
└──────────────┬──────────────────────────────┬───────────────────────┘
               │ mTLS                         │ mTLS
               ▼                             ▼
┌──────────────────────────┐    ┌─────────────────────────────────────┐
│     Keycloak 26+         │    │        .NET 9 Web API               │
│  - FIPS 140-3 mode       │    │  Middleware pipeline (ordered):     │
│  - PAR endpoint          │    │  1. TLS enforcement                 │
│  - WebAuthn AAL3 flow    │    │  2. Security headers                │
│  - Token endpoint        │    │  3. Rate limiting                   │
│  - JWKS endpoint         │    │  4. DpopValidationMiddleware        │
│  - Back-channel logout   │    │  5. TokenReplayMiddleware (Redis)   │
│  - UMA 2.0 authz         │    │  6. UseAuthentication (JWT Bearer)  │
│                          │    │  7. AcrValidationMiddleware         │
│  ┌──────────────────┐   │    │  8. UseAuthorization                │
│  │ Infinispan cluster│   │    │                                     │
│  │ (session store)   │   │    │  Controllers:                       │
│  └──────────────────┘   │    │  - ProfileController                │
│                          │    │  - TokenIntrospectionController     │
│  ┌──────────────────┐   │    └─────────────────┬───────────────────┘
│  │ FIPS HSM          │   │                      │ mTLS
│  │ (signing keys)    │   │                      ▼
│  └──────────────────┘   │         ┌─────────────────────────┐
└──────────────────────────┘         │   Redis (jti cache)     │
               │ JWKS (mTLS)         │   - TLS + auth          │
               └─────────────────────│   - Key: replay:jti:*   │
                                     │   - TTL = token lifetime │
                                     └─────────────────────────┘
                                                 │
                              ┌──────────────────┼───────────────┐
                              ▼                  ▼               ▼
                        OTel Collector      SIEM (Splunk)    Prometheus
```

### 2.2 Solution Structure (.NET)

```
src/
├── FortressApi.Api/                         ← Presentation layer
│   ├── Controllers/
│   │   ├── ProfileController.cs
│   │   └── HealthController.cs
│   ├── Middleware/
│   │   ├── DpopValidationMiddleware.cs      ← DPoP proof verification
│   │   ├── TokenReplayMiddleware.cs         ← jti Redis cache
│   │   ├── AcrValidationMiddleware.cs       ← ACR claim enforcement
│   │   └── SecurityHeadersMiddleware.cs     ← Response security headers
│   ├── Authorization/
│   │   ├── Requirements/
│   │   │   ├── AcrRequirement.cs
│   │   │   └── ScopeRequirement.cs
│   │   └── Handlers/
│   │       ├── AcrAuthorizationHandler.cs
│   │       └── ScopeAuthorizationHandler.cs
│   ├── Filters/
│   │   └── ProblemDetailsFactory.cs         ← RFC 7807 uniform errors
│   ├── OpenApi/
│   │   └── SecuritySchemeDocumentFilter.cs
│   └── Program.cs
│
├── FortressApi.Application/                 ← Use cases
│   ├── Auth/
│   │   ├── Queries/
│   │   │   └── GetCurrentUserQuery.cs
│   │   └── Models/
│   │       ├── TokenClaims.cs               ← Parsed, validated claims model
│   │       └── DpopProof.cs                 ← Parsed DPoP proof model
│
├── FortressApi.Infrastructure/              ← External integrations
│   ├── Auth/
│   │   ├── DpopProofValidator.cs            ← Core DPoP proof validation logic
│   │   ├── JtiReplayCache.cs                ← Redis jti store
│   │   ├── KeycloakJwksProvider.cs          ← JWKS caching + rotation
│   │   └── AcrClaimsTransformer.cs          ← ACR claim normalization
│   ├── Cache/
│   │   └── RedisConnectionFactory.cs
│   └── Telemetry/
│       ├── AuthTelemetry.cs                 ← Named metrics + spans
│       └── SecurityEventEmitter.cs          ← SIEM event publisher
│
└── FortressApi.Tests/
    ├── Unit/
    │   ├── DpopProofValidatorTests.cs
    │   ├── JtiReplayCacheTests.cs
    │   ├── AcrAuthorizationHandlerTests.cs
    │   └── TokenClaimsTests.cs
    └── Integration/
        ├── AuthFlowIntegrationTests.cs      ← Full PAR→Token→API flow
        ├── SecurityScenarioTests.cs         ← All S-XX scenarios
        └── Fixtures/
            ├── KeycloakFixture.cs           ← Testcontainers Keycloak
            └── RedisFixture.cs              ← Testcontainers Redis
```

---

## 3. Keycloak Implementation Plan

### 3.1 Realm Configuration

```json
{
  "realm": "fortress-gov",
  "enabled": true,
  "displayName": "FortressAPI Government",
  "sslRequired": "all",
  "registrationAllowed": false,
  "loginWithEmailAllowed": true,
  "duplicateEmailsAllowed": false,
  "resetPasswordAllowed": false,
  "editUsernameAllowed": false,
  "bruteForceProtected": true,
  "permanentLockout": false,
  "maxFailureWaitSeconds": 900,
  "minimumQuickLoginWaitSeconds": 60,
  "waitIncrementSeconds": 60,
  "quickLoginCheckMilliSeconds": 1000,
  "maxDeltaTimeSeconds": 600,
  "failureFactor": 5,
  "accessTokenLifespan": 300,
  "accessTokenLifespanForImplicitFlow": 0,
  "ssoSessionIdleTimeout": 1800,
  "ssoSessionMaxLifespan": 28800,
  "offlineSessionIdleTimeout": 28800,
  "offlineSessionMaxLifespan": 28800,
  "revokeRefreshToken": true,
  "refreshTokenMaxReuse": 0
}
```

### 3.2 Client Policy — FAPI 2.0 Government Profile

```json
{
  "name": "fapi2-government-policy",
  "description": "Enforces FAPI 2.0 + DPoP for all government clients",
  "enabled": true,
  "conditions": [
    {
      "condition": "any-client",
      "configuration": {}
    }
  ],
  "profiles": ["fapi2-government-profile"]
}
```

```json
{
  "name": "fapi2-government-profile",
  "executors": [
    { "executor": "pkce-enforcer",             "configuration": { "allow-method": ["S256"] } },
    { "executor": "dpop-enforcer",             "configuration": { "dpop-bound-access-tokens": "true" } },
    { "executor": "par-enforcer",              "configuration": { "par-required": "true" } },
    { "executor": "secure-signing-algorithm",  "configuration": { "algorithm": ["PS256", "ES256"] } },
    { "executor": "secure-session",            "configuration": { "max-sessions": "3" } },
    { "executor": "hold-of-key-enforcer",      "configuration": { "every-endpoint": "true" } }
  ]
}
```

### 3.3 WebAuthn Authenticator Policy

```json
{
  "webAuthnPolicyRpEntityName": "FortressAPI Government",
  "webAuthnPolicyRpId": "agency.gov",
  "webAuthnPolicyAttestationConveyancePreference": "direct",
  "webAuthnPolicyAuthenticatorAttachment": "cross-platform",
  "webAuthnPolicyRequireResidentKey": "Yes",
  "webAuthnPolicyUserVerificationRequirement": "required",
  "webAuthnPolicySignatureAlgorithms": ["ES256", "RS256"],
  "webAuthnPolicyAvoidSameAuthenticatorRegister": false,
  "webAuthnPolicyAcceptableAaguids": [],
  "webAuthnPolicyExtraOrigins": []
}
```

### 3.4 Authentication Flow Steps

```
Flow: government-aal3-browser

REQUIRED  - Auth Note Checker
REQUIRED  - Cookie
ALTERNATIVE:
  REQUIRED  - Username Password Form
  REQUIRED  - WebAuthn Authenticator
    [Configuration]
    User Verification: REQUIRED
    Attestation: DIRECT  
    Timeout: 300 seconds
    MDS3 validation: ENABLED
CONDITIONAL (WebAuthn failures ≥ 3 in session):
  REQUIRED  - OTP Form (TOTP recovery only)

Post-login:
  REQUIRED  - ACR Loa Condition Check
    → Maps this flow to acr3
```

---

## 4. .NET Implementation Plan

### 4.1 Program.cs — Service Registration & Middleware Pipeline

```csharp
// ── Authentication ──────────────────────────────────────────────────
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority             = config["Keycloak:Authority"];
        options.Audience              = config["Keycloak:Audience"];
        options.RequireHttpsMetadata  = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer            = true,
            ValidateAudience          = true,
            ValidateLifetime          = true,
            ClockSkew                 = TimeSpan.Zero,     // ZERO tolerance
            ValidAlgorithms           = ["PS256", "ES256"],
            RequireSignedTokens       = true,
            RequireExpirationTime     = true,
            NameClaimType             = "sub",
            RoleClaimType             = "realm_access.roles",
        };
        // Automatic JWKS refresh
        options.RefreshOnIssuerKeyNotFound = true;
    });

// ── Authorization ────────────────────────────────────────────────────
builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .RequireClaim("acr")
        .Build();

    options.AddPolicy(Policies.ReadProfile,
        p => p.RequireAuthenticatedUser()
               .AddRequirements(
                   new ScopeRequirement("profile"),
                   new AcrRequirement(AcrLevel.Acr2)));

    options.AddPolicy(Policies.AdminWrite,
        p => p.RequireAuthenticatedUser()
               .AddRequirements(
                   new ScopeRequirement("admin:write"),
                   new AcrRequirement(AcrLevel.Acr3)));
});

builder.Services.AddSingleton<IAuthorizationHandler, AcrAuthorizationHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, ScopeAuthorizationHandler>();

// ── Infrastructure ───────────────────────────────────────────────────
builder.Services.AddStackExchangeRedisCache(o =>
    o.ConfigurationOptions = RedisConnectionFactory.Build(config));

builder.Services.AddSingleton<IJtiReplayCache, JtiReplayCache>();
builder.Services.AddSingleton<IDpopProofValidator, DpopProofValidator>();
builder.Services.AddHttpClient<IKeycloakJwksProvider, KeycloakJwksProvider>()
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        // mTLS client certificate loaded from vault
        ClientCertificates = { CertificateLoader.LoadFromVault("keycloak-mtls-cert") }
    });

// ── OpenTelemetry ────────────────────────────────────────────────────
builder.Services
    .AddOpenTelemetry()
    .WithTracing(t => t.AddAspNetCoreInstrumentation().AddSource(AuthTelemetry.SourceName))
    .WithMetrics(m => m.AddMeter(AuthTelemetry.MeterName).AddPrometheusExporter());

// ── Middleware pipeline (ORDER IS CRITICAL) ──────────────────────────
app.UseMiddleware<SecurityHeadersMiddleware>();   // 1. Headers on all responses
app.UseRateLimiter();                            // 2. Protect auth endpoints
app.UseMiddleware<DpopValidationMiddleware>();    // 3. DPoP before auth resolves user
app.UseMiddleware<TokenReplayMiddleware>();       // 4. jti check before auth resolves user
app.UseAuthentication();                         // 5. JWT Bearer validation
app.UseMiddleware<AcrValidationMiddleware>();     // 6. ACR after identity established
app.UseAuthorization();                          // 7. Policy enforcement
```

### 4.2 DPoP Validation Middleware — Design

**Validation steps (all must pass):**

1. Extract `Authorization` header — must be `DPoP <token>`, not `Bearer <token>`
2. Extract `DPoP` header — must be present
3. Parse DPoP proof JWT header — get `alg` (must be PS256/ES256) and `jwk` (public key)
4. Verify DPoP proof JWT signature using the embedded `jwk`
5. Parse DPoP proof JWT payload:
   - `jti` — must be present (unique proof ID)
   - `htm` — must match `HttpContext.Request.Method`
   - `htu` — must match `HttpContext.Request.Scheme + "://" + Host + Path` (no query string)
   - `iat` — must be within `[now - 60s, now + 5s]`
   - `nonce` — must match the server-issued nonce (from Redis key `dpop:nonce:{client-hash}`)
6. Verify the `cnf.jkt` claim in the access token matches the JWK thumbprint in the DPoP proof
7. On any failure: return 401 with `WWW-Authenticate: DPoP error="invalid_dpop_proof", algs="PS256 ES256"`
8. After validation: issue a new nonce in the response `DPoP-Nonce` header

### 4.3 Token Replay Middleware — Design

**Algorithm:**
```
1. Wait for JWT Bearer authentication to complete (runs after UseAuthentication but jti check
   can run before user is resolved by hooking into OnTokenValidated event instead)
   
   PREFERRED APPROACH: Hook into JwtBearer OnTokenValidated event:
   
   options.Events = new JwtBearerEvents
   {
       OnTokenValidated = async ctx =>
       {
           var jti    = ctx.Principal!.FindFirst("jti")?.Value;
           var exp    = ctx.Principal!.FindFirst("exp")?.Value;
           var cache  = ctx.HttpContext.RequestServices.GetRequiredService<IJtiReplayCache>();
           
           if (string.IsNullOrEmpty(jti))
           {
               ctx.Fail("Missing jti claim");
               return;
           }
           
           var alreadySeen = await cache.ExistsAsync(jti, ctx.HttpContext.RequestAborted);
           if (alreadySeen)
           {
               // Emit security event BEFORE failing
               var telemetry = ctx.HttpContext.RequestServices
                   .GetRequiredService<ISecurityEventEmitter>();
               await telemetry.EmitAsync(SecurityEvent.TokenReplay, new { jti });
               
               ctx.Fail("Token replay detected");
               return;
           }
           
           // Store jti — TTL = remaining token lifetime
           var remainingTtl = DateTimeOffset.FromUnixTimeSeconds(long.Parse(exp!))
               - DateTimeOffset.UtcNow;
           await cache.StoreAsync(jti, remainingTtl, ctx.HttpContext.RequestAborted);
       }
   };
```

### 4.4 ACR Authorization Handler — Design

```csharp
public sealed class AcrRequirement(string minimumAcr) : IAuthorizationRequirement
{
    public string MinimumAcr { get; } = minimumAcr;
}

public sealed class AcrAuthorizationHandler 
    : AuthorizationHandler<AcrRequirement>
{
    private static readonly Dictionary<string, int> AcrRank = new()
    {
        ["acr1"] = 1,
        ["acr2"] = 2,
        ["acr3"] = 3,
    };

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AcrRequirement requirement)
    {
        var tokenAcr = context.User.FindFirst("acr")?.Value;

        if (tokenAcr is null
            || !AcrRank.TryGetValue(tokenAcr, out var tokenRank)
            || !AcrRank.TryGetValue(requirement.MinimumAcr, out var requiredRank)
            || tokenRank < requiredRank)
        {
            // Return 401 with step-up hint — NOT 403
            // The httpContext is accessed via resource if needed for the header
            context.Fail(new AuthorizationFailureReason(this,
                $"Insufficient ACR. Required: {requirement.MinimumAcr}, Got: {tokenAcr}"));
            return Task.CompletedTask;
        }

        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
```

### 4.5 Security Headers Middleware — Design

```csharp
// Applied on ALL responses — no exceptions
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["Strict-Transport-Security"]  = "max-age=63072000; includeSubDomains; preload";
    ctx.Response.Headers["Content-Security-Policy"]    = "default-src 'none'; frame-ancestors 'none'";
    ctx.Response.Headers["X-Content-Type-Options"]     = "nosniff";
    ctx.Response.Headers["X-Frame-Options"]            = "DENY";
    ctx.Response.Headers["Referrer-Policy"]            = "no-referrer";
    ctx.Response.Headers["Permissions-Policy"]         = "geolocation=(), microphone=(), camera=()";
    ctx.Response.Headers["Cache-Control"]              = "no-store";
    ctx.Response.Headers["Pragma"]                     = "no-cache";
    // Remove server identification
    ctx.Response.Headers.Remove("Server");
    ctx.Response.Headers.Remove("X-Powered-By");
    await next();
});
```

---

## 5. Data Model

### 5.1 Redis Key Schema

```
Key pattern          : replay:jti:{jti-value}
Value                : "" (empty — presence is the signal)
TTL                  : Remaining token lifetime in seconds (min 1s)
Eviction policy      : allkeys-lru (safety net — TTL is primary expiry)
Max memory policy    : Redis must be sized for peak concurrent users × 5 min token window

Key pattern          : dpop:nonce:{sha256-of-client-ip-and-clientId}
Value                : {nonce-value} (32 bytes, base64url)
TTL                  : 600 seconds (nonce must be used within 10 minutes)
```

### 5.2 Audit Log Event Schema

```json
{
  "timestamp"     : "2026-03-13T10:00:00.000Z",
  "eventType"     : "AUTH_SUCCESS | AUTH_FAILURE | TOKEN_REPLAY | TOKEN_ISSUED | LOGOUT",
  "correlationId" : "uuid-v4",
  "sub"           : "opaque-uuid",
  "clientId"      : "fortressapi-gov-client",
  "sessionId"     : "keycloak-session-id",
  "acr"           : "acr3",
  "ipHash"        : "sha256-hex",
  "userAgentHash" : "sha256-hex",
  "outcome"       : "success | failure",
  "failureReason" : "string | null",
  "dpopJkt"       : "jwk-thumbprint | null"
}
```

---

## 6. Dependencies

| Dependency | Version | Purpose | CVE Status |
|---|---|---|---|
| `Microsoft.AspNetCore.Authentication.JwtBearer` | 9.0.x | JWT Bearer auth | Clean |
| `Microsoft.AspNetCore.Authorization` | 9.0.x | Policy-based authz | Clean |
| `StackExchange.Redis` | 2.8.x | Redis jti cache | Clean |
| `Microsoft.Extensions.Caching.StackExchangeRedis` | 9.0.x | Redis integration | Clean |
| `OpenTelemetry.Extensions.Hosting` | 1.9.x | OTel SDK | Clean |
| `OpenTelemetry.Instrumentation.AspNetCore` | 1.9.x | HTTP tracing | Clean |
| `Microsoft.IdentityModel.JsonWebTokens` | 8.x | JWT parsing | Clean |
| `System.IdentityModel.Tokens.Jwt` | 8.x | JWT validation | Clean |
| Keycloak | 26.1.x | IdP / AS | FIPS verified |
| Redis | 7.4.x | Cache | Clean |

**No** `BouncyCastle` (non-FIPS) in .NET — using only `System.Security.Cryptography` FIPS-approved APIs.

---

## 7. Error Handling Strategy

### 7.1 Failure Classification

| Failure | HTTP Status | `type` URI | Log Level | SIEM? |
|---|---|---|---|---|
| Missing `Authorization` header | 401 | `/errors/unauthorized` | Information | No |
| Invalid JWT signature | 401 | `/errors/unauthorized` | Warning | Yes (count spike) |
| Expired JWT | 401 | `/errors/token-expired` | Information | No |
| Invalid algorithm (non-PS256/ES256) | 401 | `/errors/unauthorized` | Warning | Yes |
| Missing/invalid DPoP header | 401 | `/errors/invalid-dpop-proof` | Warning | Yes (count spike) |
| DPoP `htm`/`htu` mismatch | 401 | `/errors/invalid-dpop-proof` | Warning | Yes |
| `jti` replay detected | 401 | `/errors/unauthorized` | Critical | Yes (immediate alert) |
| Insufficient ACR | 401 | `/errors/insufficient-auth` | Information | No |
| Insufficient scope | 403 | `/errors/forbidden` | Information | No |
| Redis unavailable | 503 | `/errors/service-unavailable` | Critical | Yes (immediate alert) |

### 7.2 ProblemDetails Response Shape

```json
{
  "type"          : "/errors/{slug}",
  "title"         : "Human-readable title",
  "status"        : 401,
  "correlationId" : "uuid-v4",
  "traceId"       : "w3c-traceparent"
}
```

**Never include**: stack traces, exception messages, inner exception details, Keycloak URLs, service names, file paths, or database query fragments.

### 7.3 Fail-Closed on Redis Unavailability

```csharp
// JtiReplayCache — fail-closed design
public async ValueTask<bool> ExistsAsync(string jti, CancellationToken ct)
{
    try
    {
        var db = _connection.GetDatabase();
        return await db.KeyExistsAsync(GetKey(jti));
    }
    catch (RedisException ex)
    {
        // Log critical — Redis is unavailable
        _logger.LogCritical(ex, "Redis unavailable during jti replay check. Failing closed.");
        _telemetry.RecordRedisFailure();
        // FAIL CLOSED: treat as if token has been seen (block the request)
        throw new ReplayCacheUnavailableException("jti replay cache unavailable", ex);
    }
}
// The middleware catches ReplayCacheUnavailableException and returns 503.
```

---

## 8. Testing Strategy

### 8.1 Test Architecture

```
Unit Tests (xUnit + Moq + FluentAssertions)
├── DpopProofValidatorTests     — all proof validation paths in isolation
├── JtiReplayCacheTests         — Redis interaction, fail-closed behavior
├── AcrAuthorizationHandlerTests — all ACR level combinations
├── TokenClaimsTests            — claim extraction, null handling
└── SecurityHeadersTests        — header presence verification

Integration Tests (xUnit + Testcontainers)
├── Fixture: KeycloakFixture    — starts Keycloak 26 container, imports realm
├── Fixture: RedisFixture       — starts Redis 7 container
├── AuthFlowIntegrationTests    — full PAR → Auth Code → Token → API flow
└── SecurityScenarioTests       — all 14 security scenarios from threat model
```

### 8.2 Test Coverage Targets

| Layer | Coverage Target |
|---|---|
| DPoP validation logic | 100% |
| jti replay cache | 100% |
| ACR handler | 100% |
| Security headers | 100% |
| Overall project | ≥ 85% |

### 8.3 Keycloak Integration Test Approach

Use **Testcontainers for .NET** to spin up a real Keycloak 26 instance with the imported realm config for integration tests. This avoids mocking the authorization server — security tests must run against real Keycloak behavior, not a simulated mock.

```csharp
// KeycloakFixture.cs
public sealed class KeycloakFixture : IAsyncLifetime
{
    private readonly KeycloakContainer _container = new KeycloakBuilder()
        .WithImage("quay.io/keycloak/keycloak:26.1")
        .WithEnvironment("KC_FEATURES", "fips:preview,dpop,par")
        .WithImportRealm("./TestData/fortress-gov-realm.json")
        .Build();

    public string AuthorityUrl => _container.GetAuthServerAddress() + "/realms/fortress-gov";
    public async Task InitializeAsync() => await _container.StartAsync();
    public async Task DisposeAsync()    => await _container.StopAsync();
}
```

---

## 9. Rollout Strategy

| Phase | Scope | Duration | Rollback Trigger |
|---|---|---|---|
| 0 — Dark Launch | Internal platform team, `feature.auth.dpop-flow = false` | 2 days | Any P0 |
| 1 — Internal Canary | Internal users only, flag `true` | 3 days | Auth error rate > 1% |
| 2 — Staged | 25% → 100% government employees | 7 days | Auth error rate > 0.5% |
| 3 — GA | Feature flag removed from code | After 14 days stable | |

---

## 10. Definition of Done

- [ ] All SPEC-0001 functional requirements (FR-01 to FR-34) implemented and tested
- [ ] All 14 threat model mitigations verified by integration tests
- [ ] SAST: zero HIGH/CRITICAL findings
- [ ] Dependency scan: zero CRITICAL CVEs
- [ ] DPoP fail-closed Redis behavior verified
- [ ] Algorithm rejection (RS256) verified
- [ ] `ClockSkew = Zero` verified (expired tokens rejected immediately)
- [ ] All security headers present on every response
- [ ] OTel traces visible end-to-end in staging
- [ ] SIEM alert rules deployed and tested with synthetic events
- [ ] Keycloak config committed as IaC and applied via CI pipeline
- [ ] OpenAPI 3.1 spec updated
- [ ] Security reviewer PR approval on all security-tagged tasks
