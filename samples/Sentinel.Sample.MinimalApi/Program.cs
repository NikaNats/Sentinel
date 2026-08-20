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

    // OpenTelemetry configuration (docs/OTEL_DOTNET_INTEGRATION_SNIPPET.md)
    builder.Services.AddOpenTelemetry()
        .ConfigureResource(resource => resource
            .AddService(serviceName: builder.Configuration["OTEL_SERVICE_NAME"] ?? "Sentinel.Sample.MinimalApi")
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
            .AddOtlpExporter())
        .WithLogging(logging =>
        {
            // Structured security events (TOKEN_REPLAY_ALERT, DPOP_FAILURE, ...) are only
            // shipped to the OTLP endpoint (collector -> Loki) when one is configured.
            // Without an endpoint the in-process logger still emits them locally.
            if (!string.IsNullOrWhiteSpace(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]))
            {
                logging.AddOtlpExporter();
            }
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
    // Force strict HTML-safe JSON output (see Sentinel.AspNetCore extension for
    // the rationale): ASP.NET Core's Minimal API pipeline defaults to
    // UnsafeRelaxedJsonEscaping, so stored <script> markup would be reflected
    // raw. This host sets it again explicitly (belt-and-suspenders).
    options.SerializerOptions.Encoder = JavaScriptEncoder.Default;
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, SampleJsonContext.Default);
});

// Loaded ONCE at startup and shared by every TLS 1.3 client (JwtBearer backchannel
// + outbound HttpClient factories). Previously created per-factory-invocation and
// captured in a callback closure, leaking one native X509Certificate2 handle per
// client. Disposed on application stop via IHostApplicationLifetime.
#pragma warning disable CA2000 // Ownership transfers to the handler closures; disposed via app.Lifetime.ApplicationStopped.
X509Certificate2? trustedCa = null;
if (!string.IsNullOrWhiteSpace(localCaPath) && File.Exists(localCaPath))
{
    var pem = File.ReadAllText(localCaPath);
    var certStart = pem.IndexOf("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal);
    var certEnd = pem.IndexOf("-----END CERTIFICATE-----", StringComparison.Ordinal);
    if (certStart >= 0 && certEnd >= 0)
    {
        // Extract Base64 payload between PEM headers, strip ALL whitespace (handles CRLF/BOM),
        // decode to raw DER bytes, then load certificate via X509CertificateLoader (no obsolescence).
        var headerLen = "-----BEGIN CERTIFICATE-----".Length;
        var base64 = pem.Substring(certStart + headerLen, certEnd - certStart - headerLen);
        base64 = Regex.Replace(base64, @"\s+", "");
        var derBytes = Convert.FromBase64String(base64);
        trustedCa = X509CertificateLoader.LoadCertificate(derBytes);
    }
    else
    {
        // Fallback: assume DER file
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

                // Static, safe header for WWW-Authenticate (RFC 6750) - no user-controlled content
                context.Response.Headers.Append("WWW-Authenticate",
                    "Bearer error=\"invalid_token\", error_description=\"Authentication required\"");

                // Detailed error goes ONLY into the JSON body (RFC 7807)
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
                // Enterprise Cryptographic & PKI Lifecycle: kid-miss telemetry
                // JwtBearerHandler natively calls ConfigurationManager.RequestRefresh()
                // on SecurityTokenSignatureKeyNotFoundException; we observe and record.
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
        // Use default HttpClient (system trust store) for JWKS fetch; CA is in system trust store via update-ca-certificates.
        // options.Backchannel = new HttpClient(tls13HandlerFactory());

        var configuredAuthority = keycloakSection["Authority"] ?? string.Empty;
        var allowedIssuers = new List<string> { configuredAuthority };

        var testPublicKey = builder.Configuration["Security:TestPublicKey"];
        // Zero Dev Bypasses: the static test key is honoured ONLY in development.
        // In any other environment a stray Security__TestPublicKey config value must
        // NOT downgrade validation (no static key, no 60s clock skew, no disabled
        // OIDC discovery/JWKS rotation).
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

    // Zero Dev Bypasses: static test-key validation (and its 60s clock skew) is
    // strictly development-only. Production always validates against the Keycloak
    // JWKS with ClockSkew = TimeSpan.Zero.
    if (isDevelopment && !string.IsNullOrWhiteSpace(testPublicKey))
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

        // Enterprise Cryptographic & PKI Lifecycle: configure JWKS refresh interval
        // Default RefreshInterval=30s (DoS protection per ASP.NET Core team guidance).
        // Shorter interval = faster rotation convergence; operator-tunable.
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
        sp.GetService<
            IConfigurationManager<OpenIdConnectConfiguration>>() // GetService უსაფრთხოდ დააბრუნებს null-ს თუ არ არსებობს
    ));


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
    options.AddPolicy("profile", context =>
        RateLimitPartition.GetSlidingWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
            _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 20,
                Window = TimeSpan.FromSeconds(10),
                SegmentsPerWindow = 2,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 5
            }));
});

builder.Services.AddSentinelAspNetCore().AddAll().ConfigureAcrRanking();
builder.Services.AddSingleton<DocumentRepository>();

var app = builder.Build();

// Release the single shared trusted-CA handle on shutdown (see tls13HandlerFactory above).
// Use ApplicationStopping so in-flight outbound TLS calls during grace period still work.
if (trustedCa is not null)
{
    app.Lifetime.ApplicationStopping.Register(trustedCa.Dispose);
}

    // RFC 7807 ProblemDetails globally - no Developer Exception Page (Zero Dev Bypasses)
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
// CorrelationId/DPoP must run BEFORE authentication so the correlation id baggage is
// attached before token validation and SIEM security events (TOKEN_REPLAY_ALERT) emit.
app.UseSentinelPreAuthenticationSecurity();
app.UseAuthentication();
app.UseAuthorization();
// mTLS binding + ACR validation require an authenticated principal.
app.UseSentinelPostAuthenticationSecurity();
app.MapOpenApi();
app.MapPrometheusScrapingEndpoint(); // GET /metrics - scraped by Prometheus (SRE soak/spike/capacity gates, sre-alerts.yaml)
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
