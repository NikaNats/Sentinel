using System.Net.Security;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.DependencyInjection;
using Sentinel.AspNetCore.Endpoints;
using Sentinel.AspNetCore.Extensions;
using Sentinel.Infrastructure.Auth;
using Sentinel.Infrastructure.DependencyInjection;
using Sentinel.Keycloak.Extensions;
using Sentinel.Keycloak.Services;
using Sentinel.RAR.Extensions;
using Sentinel.Redis.Extensions;
using Sentinel.Sample.MinimalApi;
using Sentinel.Sample.MinimalApi.Endpoints;
using Sentinel.SdJwt;
using Sentinel.Security.Abstractions.Identity;
using Sentinel.Security.Abstractions.SSF;
using IPNetwork = System.Net.IPNetwork;
using ISsfEventProcessor = Sentinel.Security.Abstractions.SSF.ISsfEventProcessor;
using JsonOptions = Microsoft.AspNetCore.Http.Json.JsonOptions;

var builder = WebApplication.CreateBuilder(args);

var isDevelopment = builder.Environment.IsDevelopment();
var localCaPath = builder.Configuration["Security:TrustedRootCaPath"];

if (isDevelopment)
{
    builder.WebHost.ConfigureKestrel(options =>
    {
        options.ConfigureHttpsDefaults(httpsOptions =>
        {
            httpsOptions.ClientCertificateMode = ClientCertificateMode.DelayCertificate;
        });
    });
}

builder.WebHost.ConfigureKestrel(options =>
{
    if (isDevelopment)
    {
        options.ConfigureHttpsDefaults(_ =>
        {
            options.ConfigureHttpsDefaults(httpsConnectionAdapterOptions =>
            {
                httpsConnectionAdapterOptions.ClientCertificateMode = ClientCertificateMode.DelayCertificate;
            });
        });
    }

    options.Limits.MaxConcurrentConnections = 10000;
    options.Limits.MaxConcurrentUpgradedConnections = 10000;
    options.Limits.MaxRequestBodySize = 10 * 1024;
    options.Limits.MinRequestBodyDataRate = new MinDataRate(100, TimeSpan.FromSeconds(10));
    options.Limits.MinResponseDataRate = new MinDataRate(100, TimeSpan.FromSeconds(10));
    options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
});

builder.Services.AddOpenApi();

var allowedCorsOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
if (allowedCorsOrigins.Length > 0)
{
    builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(policy => policy
            .WithOrigins(allowedCorsOrigins)
            .WithMethods("GET", "POST", "PUT", "PATCH", "DELETE")
            .WithHeaders("Authorization", "DPoP", "Content-Type", "Idempotency-Key", "SSF-Auth-Token")
            .WithExposedHeaders("DPoP-Nonce", "WWW-Authenticate"));
    });
}

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
    options.ForwardLimit = 2;
    var trustedProxies = builder.Configuration.GetSection("Sentinel:Mtls:TrustedProxies").Get<string[]>() ??
                         ["127.0.0.1/32", "::1/128"];
    foreach (var cidr in trustedProxies)
    {
        if (IPNetwork.TryParse(cidr, out var network))
        {
            options.KnownIPNetworks.Add(network);
        }
    }
});

builder.Services.Configure<JsonOptions>(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, SampleJsonContext.Default);
});

var tls13HandlerFactory = () =>
{
    var handler = new SocketsHttpHandler
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        SslOptions = new SslClientAuthenticationOptions
        {
            EnabledSslProtocols = SslProtocols.Tls13,
            CertificateRevocationCheckMode = isDevelopment
                ? X509RevocationMode.NoCheck
                : X509RevocationMode.Online
        }
    };

    if (!string.IsNullOrWhiteSpace(localCaPath) && File.Exists(localCaPath))
    {
        var trustedCa = X509Certificate2.CreateFromPemFile(localCaPath);
        handler.SslOptions.RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
        {
            if (errors == SslPolicyErrors.None)
            {
                return true;
            }

            using var customChain = new X509Chain();
            customChain.ChainPolicy.RevocationMode = isDevelopment
                ? X509RevocationMode.NoCheck
                : X509RevocationMode.Online;
            customChain.ChainPolicy.DisableCertificateDownloads = true;
            customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            customChain.ChainPolicy.CustomTrustStore.Add(trustedCa);

            return customChain.Build((X509Certificate2)cert!);
        };
    }
    else if (isDevelopment)
    {
        var devThumbprint = builder.Configuration["Security:ExpectedDevCertificateThumbprint"];
        handler.SslOptions.RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
        {
            if (errors == SslPolicyErrors.None)
            {
                return true;
            }

            if (cert is X509Certificate2 xc && !string.IsNullOrWhiteSpace(devThumbprint))
            {
                var actualThumbprint = xc.GetCertHashString(HashAlgorithmName.SHA256);
                return string.Equals(actualThumbprint, devThumbprint, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        };
    }

    return handler;
};

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var authHeader = context.Request.Headers.Authorization.ToString();
                if (authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
                {
                    context.Token = authHeader["DPoP ".Length..].Trim();
                }

                return Task.CompletedTask;
            },
            OnTokenValidated = async context =>
            {
                var jwt = (JsonWebToken)context.SecurityToken;
                var identity = (ClaimsIdentity)context.Principal!.Identity!;

                var expClaim = jwt.Claims.FirstOrDefault(c => c.Type == "exp")?.Value
                               ?? new DateTimeOffset(jwt.ValidTo).ToUnixTimeSeconds().ToString();
                var sidClaim = jwt.Claims.FirstOrDefault(c => c.Type == "sid")?.Value;
                var subClaim = jwt.Subject ?? jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
                var acrClaim = jwt.Claims.FirstOrDefault(c => c.Type == "acr")?.Value;
                var scopeClaim = jwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value;

                if (!identity.HasClaim(c => c.Type == "exp"))
                {
                    identity.AddClaim(new Claim("exp", expClaim));
                }

                if (!identity.HasClaim(c => c.Type == "sid") && !string.IsNullOrEmpty(sidClaim))
                {
                    identity.AddClaim(new Claim("sid", sidClaim));
                }

                if (!identity.HasClaim(c => c.Type == "sub") && !string.IsNullOrEmpty(subClaim))
                {
                    identity.AddClaim(new Claim("sub", subClaim));
                }

                if (!identity.HasClaim(c => c.Type == "acr") && !string.IsNullOrEmpty(acrClaim))
                {
                    identity.AddClaim(new Claim("acr", acrClaim));
                }

                if (!identity.HasClaim(c => c.Type == "scope") && !string.IsNullOrEmpty(scopeClaim))
                {
                    identity.AddClaim(new Claim("scope", scopeClaim));
                }

                var validationService =
                    context.HttpContext.RequestServices.GetRequiredService<TokenValidationService>();
                var outcome = await validationService.ValidateAsync(context.Principal!, context.HttpContext,
                    context.HttpContext.RequestAborted);
                if (!outcome.IsSuccess)
                {
                    context.Fail(outcome.FailureException ??
                                 new SecurityTokenException(outcome.FailureReason ?? "Token validation failed."));
                }
            },
            OnChallenge = async context =>
            {
                context.HandleResponse();
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/problem+json; charset=utf-8";

                var errorDetail = !string.IsNullOrWhiteSpace(context.ErrorDescription)
                    ? context.ErrorDescription
                    : context.AuthenticateFailure?.Message;

                if (string.IsNullOrWhiteSpace(errorDetail))
                {
                    errorDetail = "Missing or invalid token";
                }

                context.Response.Headers.Append("WWW-Authenticate",
                    $"Bearer error=\"invalid_token\", error_description=\"{errorDetail}\"");

                var problem = new ProblemDetails
                {
                    Type = "/errors/unauthorized",
                    Title = "Authentication required",
                    Status = StatusCodes.Status401Unauthorized,
                    Detail = errorDetail
                };

                var json = JsonSerializer.Serialize(problem, SampleJsonContext.Default.ProblemDetails);
                await context.Response.WriteAsync(json);
            }
        };

        var keycloakSection = builder.Configuration.GetSection("Keycloak");
        options.Authority = keycloakSection["Authority"];
        options.Audience = keycloakSection["Audience"];

        options.RequireHttpsMetadata = !string.Equals(keycloakSection["RequireHttpsMetadata"], "false",
            StringComparison.OrdinalIgnoreCase);
        options.Backchannel = new HttpClient(tls13HandlerFactory());

        var configuredAuthority = keycloakSection["Authority"] ?? string.Empty;
        var allowedIssuers = new List<string> { configuredAuthority };

        var testPublicKey = builder.Configuration["Security:TestPublicKey"];
        if ((isDevelopment || !string.IsNullOrWhiteSpace(testPublicKey)) &&
            !configuredAuthority.Contains("localhost:8443", StringComparison.OrdinalIgnoreCase))
        {
            allowedIssuers.Add("https://localhost:8443/realms/sentinel");
        }

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuers = allowedIssuers,
            ValidateAudience = true,
            ValidAudience = keycloakSection["Audience"],
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            RequireSignedTokens = true,
            ValidAlgorithms = ["PS256", "ES256"]
        };
    });

builder.Services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
{
    var keycloakSection = builder.Configuration.GetSection("Keycloak");
    var configuredAuthority = keycloakSection["Authority"] ?? string.Empty;

    var allowedIssuers = new List<string> { configuredAuthority };

    var testPublicKey = builder.Configuration["Security:TestPublicKey"];
    if ((isDevelopment || !string.IsNullOrWhiteSpace(testPublicKey)) &&
        !configuredAuthority.Contains("localhost:8443", StringComparison.OrdinalIgnoreCase))
    {
        allowedIssuers.Add("https://localhost:8443/realms/sentinel");
    }

    options.TokenValidationParameters.ValidateIssuer = true;
    options.TokenValidationParameters.ValidIssuers = allowedIssuers;
    options.TokenValidationParameters.ValidateAudience = true;
    options.TokenValidationParameters.ValidAudience = keycloakSection["Audience"];
    options.TokenValidationParameters.ValidateLifetime = true;
    options.TokenValidationParameters.ValidateIssuerSigningKey = true;

    if (!string.IsNullOrWhiteSpace(testPublicKey))
    {
        options.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(60);

        var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(testPublicKey), out _);

        var key = new ECDsaSecurityKey(ecdsa) { KeyId = "test-authority-key" };
        options.TokenValidationParameters.IssuerSigningKey = key;
        options.TokenValidationParameters.IssuerSigningKeys = new[] { key };

        options.ConfigurationManager = null;
        options.MetadataAddress = null!;
        options.Authority = null!;
    }
    else
    {
        options.TokenValidationParameters.ClockSkew = TimeSpan.Zero;
    }
});

builder.Services
    .AddRedisSecurityCaches(builder.Configuration.GetSection("Sentinel:Redis"))
    .AddApplicationLayer()
    .AddSsfProcessing(builder.Configuration)
    .AddRarValidation(builder.Configuration)
    .AddKeycloakIntegration(builder.Configuration.GetSection("Sentinel:Keycloak"))
    .AddInfrastructureLayer(builder.Configuration);

_ = builder.Services.AddHttpClient("keycloak-admin").ConfigurePrimaryHttpMessageHandler(tls13HandlerFactory);
_ = builder.Services.AddHttpClient(typeof(IUmaPermissionService).FullName!)
    .ConfigurePrimaryHttpMessageHandler(tls13HandlerFactory);
_ = builder.Services.AddHttpClient(typeof(ITokenRefreshService).FullName!)
    .ConfigurePrimaryHttpMessageHandler(tls13HandlerFactory);
_ = builder.Services.AddHttpClient(typeof(ITokenExchangeService).FullName!)
    .ConfigurePrimaryHttpMessageHandler(tls13HandlerFactory);
_ = builder.Services.AddHttpClient(typeof(IIdentityRegistry).FullName!)
    .ConfigurePrimaryHttpMessageHandler(tls13HandlerFactory);
_ = builder.Services.AddHttpClient(typeof(IUserProfileManager).FullName!)
    .ConfigurePrimaryHttpMessageHandler(tls13HandlerFactory);
_ = builder.Services.AddHttpClient(typeof(IIdentityFederationProvider).FullName!)
    .ConfigurePrimaryHttpMessageHandler(tls13HandlerFactory);
_ = builder.Services.AddHttpClient(typeof(IAuthRevocationService).FullName!)
    .ConfigurePrimaryHttpMessageHandler(tls13HandlerFactory);
_ = builder.Services.AddHttpClient(typeof(KeycloakConfigurationManager).FullName!)
    .ConfigurePrimaryHttpMessageHandler(tls13HandlerFactory);
_ = builder.Services.AddHttpClient(typeof(ICaptchaService).FullName!)
    .ConfigurePrimaryHttpMessageHandler(tls13HandlerFactory);

builder.Services.AddSingleton(
    Options.Create(new SdJwtVerificationOptions
    {
        RequireKeyBindingNonce = false,
        KeyBindingMaxAgeSeconds = 300,
        AllowedClockSkewSeconds = 60,
        AllowedDisclosureHashAlgorithms = ["sha-256"]
    }));
builder.Services.AddSingleton(sp => sp.GetRequiredService<IOptions<SdJwtVerificationOptions>>().Value);

builder.Services.AddTransient<SdJwtPresenter>();
builder.Services.AddTransient<ISdJwtTokenValidator, SampleSdJwtTokenValidator>();
builder.Services.AddSingleton<ISsfTokenValidator, BypassSsfTokenValidator>();
builder.Services
    .AddScoped<Sentinel.Security.Abstractions.Security.IAuthRevocationService, SecurityAuthRevocationServiceAdapter>();
builder.Services.AddScoped<Sentinel.Application.Auth.Interfaces.ISsfEventProcessor, SecuritySsfEventProcessorAdapter>();

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("ScopeProfile", policy =>
        policy.RequireAuthenticatedUser().AddRequirements(new ScopeRequirement("profile")))
    .AddPolicy("ScopeDocumentsRead", policy =>
        policy.RequireAuthenticatedUser().AddRequirements(new ScopeRequirement("documents:read")))
    .AddPolicy("ScopeDocumentsWrite", policy =>
        policy.RequireAuthenticatedUser().AddRequirements(new ScopeRequirement("documents:write")));

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("profile", _ =>
        RateLimitPartition.GetConcurrencyLimiter("profile-global", _ => new ConcurrencyLimiterOptions
        {
            PermitLimit = 1,
            QueueLimit = 2,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst
        }));
});

builder.Services.AddSentinelAspNetCore().AddAll().ConfigureAcrRanking();
builder.Services.AddSingleton<DocumentRepository>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler(errorApp =>
    {
        errorApp.Run(async context =>
        {
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            context.Response.ContentType = "application/problem+json; charset=utf-8";

            var problem = new ProblemDetails
            {
                Type = "/errors/internal",
                Title = "Unexpected error",
                Detail = "An unexpected error occurred while processing the request.",
                Status = StatusCodes.Status500InternalServerError,
                Extensions = { ["traceId"] = context.TraceIdentifier }
            };

            var json = JsonSerializer.Serialize(problem, SampleJsonContext.Default.ProblemDetails);
            await context.Response.WriteAsync(json);
        });
    });
}

app.UseForwardedHeaders();
app.UseHttpsRedirection();
if (allowedCorsOrigins.Length > 0)
{
    app.UseCors();
}
app.UseRateLimiter();
app.UseAuthentication();
app.UseSentinelSecurityPipeline();
app.UseAuthorization();
app.MapOpenApi();
app.MapScalarApiReference("/docs", options =>
{
    options.Title = "Sentinel API Documentation";
    options.Theme = ScalarTheme.Moon;
    options.DefaultHttpClient =
        new KeyValuePair<ScalarTarget, ScalarClient>(ScalarTarget.CSharp, ScalarClient.HttpClient);
});

const string securityPrefix = "v1";
const string documentsPrefix = "v1/documents";
const string financePrefix = "api/v1/finance";
const string showcasePrefix = "v1";

app.MapGet("/", () => TypedResults.Ok(
    new SampleInfoResponse("Sentinel.Sample.MinimalApi", "/docs",
        new EndpointMap("/healthz", $"/{securityPrefix}", $"/{documentsPrefix}", $"/{financePrefix}",
            $"/{showcasePrefix}")))).AllowAnonymous();
app.MapGet("/healthz", () => TypedResults.Ok(new HealthResponse("ok", DateTimeOffset.UtcNow))).AllowAnonymous();

app.MapSentinelSecurity();
app.MapDocumentEndpoints(documentsPrefix);
app.MapFinanceEndpoints(financePrefix);
app.MapShowcaseEndpoints(showcasePrefix);

app.Run();

internal sealed record SampleInfoResponse(string Service, string Docs, EndpointMap Endpoints);

internal sealed record EndpointMap(string Health, string Security, string Documents, string Finance, string Showcase);

internal sealed record HealthResponse(string Status, DateTimeOffset Utc);

internal sealed class SecurityAuthRevocationServiceAdapter(
    IAuthRevocationService inner)
    : Sentinel.Security.Abstractions.Security.IAuthRevocationService
{
    public Task RevokeAllSessionsAsync(string subject, CancellationToken cancellationToken = default) =>
        inner.RevokeAllSessionsAsync(subject, cancellationToken);
}

internal sealed class SecuritySsfEventProcessorAdapter(
    ISsfEventProcessor inner)
    : Sentinel.Application.Auth.Interfaces.ISsfEventProcessor
{
    public async Task<SsfProcessResult> ProcessAsync(string setToken, CancellationToken ct)
    {
        var result = await inner.ProcessAsync(setToken, ct);
        return result.IsSuccess
            ? SsfProcessResult.Success()
            : SsfProcessResult.Invalid(result.ErrorMessage ?? "SSF processing failed");
    }
}

internal sealed class BypassSsfTokenValidator : ISsfTokenValidator
{
    public Task<SsfValidationResult> ValidateAsync(string setToken, CancellationToken cancellationToken = default)
    {
        try
        {
            var jwt = new JsonWebToken(setToken);
            var eventsStr = jwt.Claims.FirstOrDefault(c => c.Type == "events")?.Value;
            var eventsElement = JsonDocument.Parse(eventsStr ?? "{}").RootElement;

            var events = new Dictionary<string, JsonElement>();
            foreach (var prop in eventsElement.EnumerateObject())
            {
                events[prop.Name] = prop.Value.Clone();
            }

            var token = new SsfEventToken(
                jwt.Issuer,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Guid.NewGuid().ToString("N"),
                "sentinel-api",
                jwt.Subject,
                events);

            return Task.FromResult(SsfValidationResult.Success(token));
        }
        catch (ArgumentException ex)
        {
            return Task.FromResult(SsfValidationResult.Fail(ex.Message));
        }
        catch (JsonException ex)
        {
            return Task.FromResult(SsfValidationResult.Fail(ex.Message));
        }
    }
}
