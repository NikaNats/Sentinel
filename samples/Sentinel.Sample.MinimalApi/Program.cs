using System.Diagnostics;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Scalar.AspNetCore;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.DependencyInjection;
using Sentinel.AspNetCore.Endpoints;
using Sentinel.AspNetCore.Extensions;
using Sentinel.AspNetCore.Infrastructure;
using Sentinel.Infrastructure.Auth;
using Sentinel.Infrastructure.DependencyInjection;
using Sentinel.Keycloak.Extensions;
using Sentinel.Keycloak.Services;
using Sentinel.Security.Diagnostics;
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
    builder.Services.Configure<KestrelServerOptions>(options =>
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
        options.ConfigureHttpsDefaults(httpsConnectionAdapterOptions =>
        {
            httpsConnectionAdapterOptions.ClientCertificateMode = ClientCertificateMode.DelayCertificate;
        });
    }

    options.Limits.MaxConcurrentConnections = 10000;
    options.Limits.MaxConcurrentUpgradedConnections = 10000;
    options.Limits.MaxRequestBodySize = 10 * 1024;
    options.Limits.MinRequestBodyDataRate = new MinDataRate(100, TimeSpan.FromSeconds(10));
    options.Limits.MinResponseDataRate = new MinDataRate(100, TimeSpan.FromSeconds(10));
    options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
});

// Certificate hot reload (Enterprise Cryptographic & PKI Lifecycle)
if (builder.Configuration.GetSection("Kestrel:CertificateReloader:Path").Exists())
{
    builder.Services.AddKestrelCertificateReloader(builder.Configuration);
    builder.WebHost.UseKestrelCertificateReloader();
}

builder.Services.AddOpenApi();

var otlpEndpoint = builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"];

// OpenTelemetry configuration (docs/OTEL_DOTNET_INTEGRATION_SNIPPET.md)
builder.Services.AddOpenTelemetry()
    .ConfigureResource(resource => resource
        .AddService(serviceName: builder.Configuration["OTEL_SERVICE_NAME"] ?? "sentinel-api")
        .AddAttributes(new Dictionary<string, object>
        {
            ["deployment.environment"] = builder.Environment.EnvironmentName,
            ["service.version"] = typeof(Program).Assembly.GetName().Version?.ToString() ?? "unknown"
        }))
    .WithMetrics(metrics => metrics
        .AddMeter(AuthTelemetry.MeterName)
        .AddPrometheusExporter())
    .WithTracing(tracing => tracing
        .AddSource(AuthTelemetry.SourceName)
        .AddAspNetCoreInstrumentation()
        .AddOtlpExporter(options =>
        {
            if (!string.IsNullOrWhiteSpace(otlpEndpoint))
            {
                options.Endpoint = new Uri(otlpEndpoint);
            }
        }))
    .WithLogging(logging =>
    {
        if (!string.IsNullOrWhiteSpace(otlpEndpoint))
        {
            logging.AddOtlpExporter(options =>
            {
                options.Endpoint = new Uri(otlpEndpoint);
            });
        }
    }, options =>
    {
        options.IncludeFormattedMessage = true;
        options.IncludeScopes = true;
    });

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
    options.SerializerOptions.Encoder = JavaScriptEncoder.Default;
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, SampleJsonContext.Default);
});

#pragma warning disable CA2000 // Ownership transfers to handler closures; disposed via app.Lifetime.ApplicationStopping.
X509Certificate2? trustedCa = null;
if (!string.IsNullOrWhiteSpace(localCaPath) && File.Exists(localCaPath))
{
    var pem = File.ReadAllText(localCaPath);
    var certStart = pem.IndexOf("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal);
    var certEnd = pem.IndexOf("-----END CERTIFICATE-----", StringComparison.Ordinal);
    if (certStart >= 0 && certEnd >= 0)
    {
        var headerLen = "-----BEGIN CERTIFICATE-----".Length;
        var base64 = pem.Substring(certStart + headerLen, certEnd - certStart - headerLen);
        base64 = Regex.Replace(base64, @"\s+", "");
        var derBytes = Convert.FromBase64String(base64);
        trustedCa = X509CertificateLoader.LoadCertificate(derBytes);
    }
    else
    {
        trustedCa = X509CertificateLoader.LoadCertificate(File.ReadAllBytes(localCaPath));
    }
}
else
{
    Console.WriteLine($"[WARN] CA path not configured or file not found: {localCaPath}");
}
#pragma warning restore CA2000

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

    if (trustedCa is not null)
    {
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

                var detailedError = !string.IsNullOrWhiteSpace(context.ErrorDescription)
                    ? context.ErrorDescription
                    : context.AuthenticateFailure?.Message;

                if (string.IsNullOrWhiteSpace(detailedError))
                {
                    detailedError = "Missing or invalid token";
                }

                context.Response.Headers.Append("WWW-Authenticate",
                    "Bearer error=\"invalid_token\", error_description=\"Authentication required\"");

                var problem = new ProblemDetails
                {
                    Type = "/errors/unauthorized",
                    Title = "Authentication required",
                    Status = StatusCodes.Status401Unauthorized,
                    Detail = Regex.Replace(detailedError, @"[\r\n\t\x00-\x1F\x7F]", "")
                };

                var json = JsonSerializer.Serialize(problem, SampleJsonContext.Default.ProblemDetails);
                await context.Response.WriteAsync(json);
            },
            OnAuthenticationFailed = context =>
            {
                if (context.Exception is SecurityTokenSignatureKeyNotFoundException)
                {
                    try
                    {
                        var kid = "unknown";
                        var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
                        if (!string.IsNullOrWhiteSpace(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                        {
                            var token = authHeader["Bearer ".Length..].Trim();
                            var jwt = new JsonWebToken(token);
                            kid = jwt.Kid ?? "unknown";
                        }
                        var tags = new TagList { { "kid", kid } };
                        AuthTelemetry.JwksKidMisses.Add(1, tags);
                        AuthTelemetry.JwksRefreshRequests.Add(1);
                    }
#pragma warning disable CA1031
                    catch
                    {
                        AuthTelemetry.JwksKidMisses.Add(1, new TagList { { "kid", "unknown" } });
                        AuthTelemetry.JwksRefreshRequests.Add(1);
                    }
#pragma warning restore CA1031
                }

                return Task.CompletedTask;
            }
        };

        var keycloakSection = builder.Configuration.GetSection("Keycloak");
        options.Authority = keycloakSection["Authority"];
        options.Audience = keycloakSection["Audience"];

        options.RequireHttpsMetadata = !string.Equals(keycloakSection["RequireHttpsMetadata"], "false",
            StringComparison.OrdinalIgnoreCase);

        var configuredAuthority = keycloakSection["Authority"] ?? string.Empty;
        var allowedIssuers = new List<string> { configuredAuthority };

        if (configuredAuthority.Contains("keycloak:8443", StringComparison.OrdinalIgnoreCase))
        {
            allowedIssuers.Add(configuredAuthority.Replace("keycloak:8443", "localhost:8443", StringComparison.OrdinalIgnoreCase));
        }

        var testPublicKey = builder.Configuration["Security:TestPublicKey"];
        if (isDevelopment &&
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

    if (configuredAuthority.Contains("keycloak:8443", StringComparison.OrdinalIgnoreCase))
    {
        allowedIssuers.Add(configuredAuthority.Replace("keycloak:8443", "localhost:8443", StringComparison.OrdinalIgnoreCase));
    }

    var testPublicKey = builder.Configuration["Security:TestPublicKey"];
    if (isDevelopment &&
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

    if (isDevelopment && !string.IsNullOrWhiteSpace(testPublicKey))
    {
        options.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(60);

        var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(testPublicKey), out _);

        var key = new ECDsaSecurityKey(ecdsa) { KeyId = "test-authority-key" };
        options.TokenValidationParameters.IssuerSigningKey = key;
        options.TokenValidationParameters.IssuerSigningKeys = [key];

        options.ConfigurationManager = null;
        options.MetadataAddress = null!;
        options.Authority = null!;
    }
    else
    {
        options.TokenValidationParameters.ClockSkew = TimeSpan.Zero;
    }

    var refreshIntervalSeconds = keycloakSection.GetValue<int>("JwksRefreshIntervalSeconds");
    if (refreshIntervalSeconds > 0 && options.ConfigurationManager is ConfigurationManager<OpenIdConnectConfiguration> cm)
    {
        cm.RefreshInterval = TimeSpan.FromSeconds(refreshIntervalSeconds);
    }
});

builder.Services
    .AddRedisSecurityCaches(builder.Configuration.GetSection("Sentinel:Redis"))
    .AddApplicationLayer()
    .AddSsfProcessing(builder.Configuration)
    .AddRarValidation(builder.Configuration)
    .AddKeycloakIntegration(builder.Configuration.GetSection("Sentinel:Keycloak"))
    .AddInfrastructureLayer(builder.Configuration);

// Privacy-preserving hashing for GDPR/SIEM logging (64-hex daily-keyed HMAC)
builder.Services.AddSingleton<IPrivacyKeyManager>(new DefaultPrivacyKeyManager());
builder.Services.AddSingleton<IPrivacyPreservingHasher, PrivacyPreservingHasher>();

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

builder.Services.AddSingleton(Options.Create(new SdJwtVerificationOptions
{
    RequireKeyBindingNonce = false,
    KeyBindingMaxAgeSeconds = 300,
    AllowedClockSkewSeconds = 60,
    AllowedDisclosureHashAlgorithms = ["sha-256"]
}));
builder.Services.AddSingleton<SdJwtVerificationOptions>(sp =>
    sp.GetRequiredService<IOptions<SdJwtVerificationOptions>>().Value);

builder.Services.AddTransient<SdJwtPresenter>();

builder.Services.AddTransient<ISdJwtTokenValidator>(sp =>
    new SampleSdJwtTokenValidator(
        sp.GetRequiredService<IConfiguration>(),
        sp.GetRequiredService<IOptions<SdJwtVerificationOptions>>(),
        sp.GetRequiredService<IWebHostEnvironment>()
    ));

builder.Services.AddSingleton<ISsfTokenValidator>(sp =>
    new SsfTokenValidator(
        sp.GetRequiredService<IConfiguration>(),
        sp.GetRequiredService<IWebHostEnvironment>(),
        sp.GetService<IConfigurationManager<OpenIdConnectConfiguration>>()
    ));

builder.Services
    .AddScoped<Sentinel.Security.Abstractions.Security.IAuthRevocationService, SecurityAuthRevocationServiceAdapter>();
builder.Services.AddScoped<Sentinel.Application.Auth.Interfaces.ISsfEventProcessor, SecuritySsfEventProcessorAdapter>();
builder.Services.AddSingleton<Sentinel.Application.Common.Abstractions.ISessionBlacklistCache>(sp =>
    new SampleSessionBlacklistCacheAdapter(
        sp.GetRequiredService<Sentinel.Security.Abstractions.Session.ISessionBlacklistCache>(),
        sp.GetRequiredService<TimeProvider>()));

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

    options.OnRejected = static async (context, token) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.HttpContext.Response.Headers.Append("Retry-After", "10");

        var problem = new ProblemDetails
        {
            Type = "/errors/rate-limit-exceeded",
            Title = "Too Many Requests",
            Status = StatusCodes.Status429TooManyRequests,
            Detail = "Rate limit quota exceeded. Please wait before retrying.",
            Instance = context.HttpContext.Request.Path
        };

        await context.HttpContext.Response.WriteAsJsonAsync(
            problem,
            SampleJsonContext.Default.ProblemDetails,
            cancellationToken: token);
    };

    // FAPI 2.0 / NIST SP 800-63B Dual-Partition Rate Limiter:
    // authenticated traffic is keyed by the token's `sub` claim (parsed pre-auth,
    // WITHOUT signature verification - validity is enforced downstream by the DPoP
    // and JWT bearer middlewares), so rotating or spoofing X-Forwarded-For cannot
    // open fresh partitions for a valid token holder. Anonymous or malformed
    // traffic falls back to the real remote address floor.
    options.AddPolicy("profile", context => RateLimitPartition.GetSlidingWindowLimiter(
        ResolveRateLimitPartitionKey(context),
        _ => new SlidingWindowRateLimiterOptions
        {
            PermitLimit = 20,
            Window = TimeSpan.FromSeconds(10),
            SegmentsPerWindow = 2,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 5
        }));
});

static string ResolveRateLimitPartitionKey(HttpContext context)
{
    // 1. Prefer the authenticated principal when authentication already ran.
    var sub = context.User.FindFirst("sub")?.Value;
    if (!string.IsNullOrWhiteSpace(sub))
    {
        return $"sub:{sub}";
    }

    // 2. Pre-authentication parsing: read `sub` straight from the presented JWT
    //    without verifying its signature (UseRateLimiter runs before UseAuthentication).
    //    A spoofed value only buys the attacker an isolated partition for a request
    //    that fails signature validation downstream anyway.
    var authHeader = context.Request.Headers.Authorization.ToString();
    if (!string.IsNullOrWhiteSpace(authHeader))
    {
        string? rawToken = null;
        if (authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
        {
            rawToken = authHeader["DPoP ".Length..].Trim();
        }
        else if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            rawToken = authHeader["Bearer ".Length..].Trim();
        }

        if (!string.IsNullOrWhiteSpace(rawToken))
        {
            try
            {
                var handler = new JsonWebTokenHandler();
                if (handler.CanReadToken(rawToken))
                {
                    var jwt = handler.ReadJsonWebToken(rawToken);
                    var tokenSub = jwt.Subject ?? jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
                    if (!string.IsNullOrWhiteSpace(tokenSub))
                    {
                        return $"sub:{tokenSub}";
                    }
                }
            }
            catch
            {
                // Malformed tokens fall back to IP-based partitioning below.
            }
        }
    }

    // 3. Anonymous requests are floored by the real remote address.
    var remoteIp = context.Connection.RemoteIpAddress?.ToString();
    return !string.IsNullOrWhiteSpace(remoteIp) ? $"ip:{remoteIp}" : "ip:anonymous";
}

builder.Services.AddSentinelAspNetCore().AddAll().ConfigureAcrRanking();
builder.Services.AddSingleton<DocumentRepository>();

var app = builder.Build();

if (trustedCa is not null)
{
    app.Lifetime.ApplicationStopping.Register(trustedCa.Dispose);
}

app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        if (context.Response.HasStarted)
        {
            return;
        }

        var statusCode = context.Response.StatusCode != StatusCodes.Status200OK
            ? context.Response.StatusCode
            : StatusCodes.Status500InternalServerError;

        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/problem+json; charset=utf-8";

        var problem = new ProblemDetails
        {
            Type = "/errors/internal",
            Title = statusCode == StatusCodes.Status500InternalServerError
                ? "Unexpected error"
                : "Request failed",
            Detail = "An unexpected error occurred while processing the request.",
            Status = statusCode,
            Extensions = { ["traceId"] = context.TraceIdentifier }
        };

        var json = JsonSerializer.Serialize(problem, SampleJsonContext.Default.ProblemDetails);
        await context.Response.WriteAsync(json);
    });
});

app.UseForwardedHeaders();
app.UseHttpsRedirection();
if (allowedCorsOrigins.Length > 0)
{
    app.UseCors();
}

app.UseRateLimiter();
app.UseSentinelPreAuthenticationSecurity();
app.UseAuthentication();
app.UseAuthorization();
app.UseSentinelPostAuthenticationSecurity();
app.MapOpenApi();
app.MapPrometheusScrapingEndpoint();
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

app.MapGet("/", () => TypedResults.Ok(new SampleInfoResponse(
        "Sentinel.Sample.MinimalApi",
        "/docs",
        new EndpointMap("/healthz", $"/{securityPrefix}", $"/{documentsPrefix}", $"/{financePrefix}",
            $"/{showcasePrefix}"))))
    .AllowAnonymous();

app.MapGet("/healthz", () => TypedResults.Ok(new HealthResponse("ok", DateTimeOffset.UtcNow))).AllowAnonymous();

app.MapSentinelSecurity();
app.MapDocumentEndpoints(documentsPrefix);
app.MapFinanceEndpoints(financePrefix);
app.MapShowcaseEndpoints(showcasePrefix);

app.Run();

internal sealed class DefaultPrivacyKeyManager : IPrivacyKeyManager
{
    private static readonly byte[] MasterPepper =
    [
        0x5E, 0x2A, 0xC1, 0x9B, 0x77, 0x44, 0xD8, 0x13,
        0xA6, 0x0F, 0x3B, 0xE9, 0x81, 0x50, 0xCC, 0x27,
        0x92, 0x4D, 0x1E, 0xB0, 0x63, 0xFA, 0x09, 0x35,
        0xC8, 0x72, 0xE5, 0x14, 0x8D, 0x4A, 0x6F, 0xD1
    ];

    public ReadOnlySpan<byte> GetMasterPepper() => MasterPepper;
}

internal sealed record SampleInfoResponse(string Service, string Docs, EndpointMap Endpoints);

internal sealed record EndpointMap(string Health, string Security, string Documents, string Finance, string Showcase);

internal sealed record HealthResponse(string Status, DateTimeOffset Utc);

internal sealed class SecurityAuthRevocationServiceAdapter(
    IAuthRevocationService inner) : Sentinel.Security.Abstractions.Security.IAuthRevocationService
{
    public Task RevokeAllSessionsAsync(string subject, CancellationToken cancellationToken = default) =>
        inner.RevokeAllSessionsAsync(subject, cancellationToken);
}

internal sealed class SecuritySsfEventProcessorAdapter(
    ISsfEventProcessor inner) : Sentinel.Application.Auth.Interfaces.ISsfEventProcessor
{
    public async Task<SsfProcessResult> ProcessAsync(string setToken, CancellationToken ct)
    {
        var result = await inner.ProcessAsync(setToken, ct);
        return result.IsSuccess
            ? SsfProcessResult.Success()
            : SsfProcessResult.Invalid(result.ErrorMessage ?? "SSF processing failed");
    }
}

internal sealed class SampleSessionBlacklistCacheAdapter(
    Sentinel.Security.Abstractions.Session.ISessionBlacklistCache inner,
    TimeProvider timeProvider) : Sentinel.Application.Common.Abstractions.ISessionBlacklistCache
{
    public Task BlacklistSessionAsync(string sessionId, TimeSpan ttl, CancellationToken ct) =>
        inner.BlacklistSessionAsync(sessionId, timeProvider.GetUtcNow() + ttl, ct);

    public ValueTask<bool> IsSessionBlacklistedAsync(string sessionId, CancellationToken ct) =>
        new(inner.IsBlacklistedAsync(sessionId, ct));
}