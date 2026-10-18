# Sentinel

Sender-constrained token validation for ASP.NET Core (.NET 10): DPoP (RFC 9449) proof validation with nonces
and replay detection, mTLS certificate binding (RFC 8705), session revocation, ACR step-up, idempotency and
Shared Signals (SSF/CAEP) receivers. Keycloak is the reference authorization server; Redis holds replay and
nonce state. Every dependency failure fails closed.

> FAPI 2.0-oriented, not FAPI-certified. External conformance has not been established.

## Packages

| Package | Purpose |
|---|---|
| `NikaNats.Sentinel.AspNetCore` | Middleware, JwtBearer wiring, endpoints and filters (start here) |
| `NikaNats.Sentinel.DPoP` | DPoP proof validator and RFC 7638 thumbprints |
| `NikaNats.Sentinel.Redis` | Production nonce, `jti` replay and session-blacklist stores |
| `NikaNats.Sentinel.Keycloak` | Keycloak token refresh, exchange, revocation and admin clients |
| `NikaNats.Sentinel.EntityFrameworkCore` | PostgreSQL-backed stores and the hybrid L1/L2/L3 session blacklist |
| `NikaNats.Sentinel.SSF` | Security Event Token (RFC 8417) processing |
| `NikaNats.Sentinel.Rar` | Rich Authorization Requests (RFC 9396) matching |
| `NikaNats.Sentinel.SdJwt` | SD-JWT verification |
| `NikaNats.Sentinel.Providers.Vault` | HashiCorp Vault key and privacy-pepper provider |

## Minimal host

```bash
dotnet add package NikaNats.Sentinel.AspNetCore
```

```csharp
using Sentinel.Application.DependencyInjection;
using Sentinel.AspNetCore.Authentication;
using Sentinel.AspNetCore.Endpoints;
using Sentinel.AspNetCore.Extensions;
using Sentinel.Infrastructure.DependencyInjection;
using Sentinel.Keycloak.Extensions;
using Sentinel.Redis.Extensions;

var builder = WebApplication.CreateBuilder(args);
var keycloak = builder.Configuration.GetSection("Sentinel:Keycloak");

builder.Services
    .AddRedisSecurityCaches(builder.Configuration.GetSection("Sentinel:Redis"))
    .AddApplicationLayer()
    .AddSsfProcessing(builder.Configuration)
    .AddKeycloakIntegration(keycloak)
    .AddInfrastructureLayer(builder.Configuration);

builder.Services.AddSentinelHostBridges();
builder.Services.AddSentinelAspNetCore().AddAll().ConfigureAcrRanking();

// Strict defaults: exact issuer/audience, zero clock skew, PS256/ES256 only, HTTPS metadata,
// session-blacklist + jti checks after signature validation, sanitized RFC 9457 401s.
builder.Services.AddAuthentication()
    .AddSentinelJwtBearer(keycloak["Authority"]!, keycloak["Audience"]!);
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseSentinelPreAuthenticationSecurity();   // security headers, correlation id, DPoP proof validation
app.UseAuthentication();
app.UseAuthorization();
app.UseSentinelPostAuthenticationSecurity();  // mTLS cnf binding, ACR step-up

app.MapSentinelSecurity("v1");
app.Run();
```

## Required configuration

Startup fails closed (`OptionsValidationException`) until these are set:

```json
{
  "Keycloak":  { "Authority": "https://idp.example.com/realms/app", "Audience": "my-api" },
  "Sentinel": {
    "Keycloak": { "Authority": "https://idp.example.com/realms/app", "Audience": "my-api" },
    "Redis":    { "EndPoint": "redis:6379", "UseSsl": true },
    "Security": { "Captcha": { "SecretKey": "<from secret store>" } }
  },
  "Cryptography": { "ActiveKeyId": "k1", "KeyRing": { "k1": "<base64 32-byte key from secret store>" } },
  "DPoP": { "AllowedAlgorithms": [ "PS256", "ES256" ] }
}
```

`Keycloak` and `Sentinel:Keycloak` are both read by different modules today; keep them identical.

## Shared Signals (SSF) receiver

`POST {prefix}/ssf/events` is off unless `Ssf:Enabled=true`. To turn it on, register the SET validator and
require the webhook token:

```csharp
builder.Services.AddSentinelSsfTokenValidation(issuer: keycloak["Authority"]!, audience: keycloak["Audience"]!);
```

```json
{ "Ssf": { "Enabled": true, "RequireAuthToken": true, "AuthToken": "<from secret store>" } }
```

## Production checklist

- Register a real `IIdempotencyStore`. The in-memory default is refused at startup outside Development.
- Provide the privacy pepper from a secret store (`AddVaultPrivacyHardening`), never a hard-coded key.
- Set `Sentinel:Redis:UseSsl=true`. Redis outages fail closed (503); there is no in-memory fallback.
- Pin outbound TLS: pass your hardened `HttpMessageHandler` via the `configure` callback of `AddSentinelJwtBearer`.
- Turn on `FeatureFlags:Auth:JtiReplayEnforcement` for single-use access tokens.

## Links

- Source, docs and threat model: https://github.com/NikaNats/Sentinel
- Security policy and reporting: https://github.com/NikaNats/Sentinel/blob/main/SECURITY.md
- Reference host: https://github.com/NikaNats/Sentinel/tree/main/samples/Sentinel.Sample.MinimalApi
