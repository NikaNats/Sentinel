using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.DependencyInjection;
using Sentinel.AspNetCore.Endpoints;
using Sentinel.AspNetCore.Extensions;
using Sentinel.Infrastructure.DependencyInjection;
using Sentinel.Keycloak.Extensions;
using Sentinel.Keycloak.Services;
using Sentinel.Redis.Extensions;
using Sentinel.Sample.MinimalApi;
using Sentinel.Sample.MinimalApi.Endpoints;
using Sentinel.SdJwt;
using Sentinel.Security.Abstractions.Identity;
using IPNetwork = System.Net.IPNetwork;

var builder = WebApplication.CreateBuilder(args);

if (builder.Environment.IsDevelopment())
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
    if (builder.Environment.IsDevelopment())
    {
        options.ConfigureHttpsDefaults(httpsOptions =>
        {
            httpsOptions.ClientCertificateMode = ClientCertificateMode.DelayCertificate;
        });
    }

    options.Limits.MaxConcurrentConnections = 10000;
    options.Limits.MaxConcurrentUpgradedConnections = 10000;

    options.Limits.MaxRequestBodySize = 10 * 1024; // 10 KB

    options.Limits.MinRequestBodyDataRate = new MinDataRate(100, TimeSpan.FromSeconds(10));
    options.Limits.MinResponseDataRate = new MinDataRate(100, TimeSpan.FromSeconds(10));

    options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
});

builder.Services.AddOpenApi();

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor
                               | ForwardedHeaders.XForwardedProto;

    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
    options.ForwardLimit = 2;
    var trustedProxies = builder.Configuration.GetSection("Sentinel:Mtls:TrustedProxies").Get<string[]>()
                         ?? ["127.0.0.1/32", "::1/128"];

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

var tls13HandlerFactory = () => new SocketsHttpHandler
{
    SslOptions = new SslClientAuthenticationOptions
    {
        EnabledSslProtocols = SslProtocols.Tls13,
        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        RemoteCertificateValidationCallback = null
    }
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
            }
        };

        var keycloakSection = builder.Configuration.GetSection("Keycloak");
        options.Authority = keycloakSection["Authority"];
        options.Audience = keycloakSection["Audience"];
        options.RequireHttpsMetadata = true;
        options.Backchannel = new HttpClient(tls13HandlerFactory());

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services
    .AddRedisSecurityCaches(builder.Configuration.GetSection("Sentinel:Redis"))
    .AddApplicationLayer()
    .AddSsfProcessing(builder.Configuration)
    .AddKeycloakIntegration(builder.Configuration.GetSection("Sentinel:Keycloak"))
    .AddInfrastructureLayer(builder.Configuration);

_ = builder.Services.AddHttpClient("keycloak-admin")
    .ConfigurePrimaryHttpMessageHandler(tls13HandlerFactory);

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

builder.Services.AddSingleton(new SdJwtVerificationOptions
{
    RequireKeyBindingNonce = false,
    KeyBindingMaxAgeSeconds = 300,
    AllowedClockSkewSeconds = 60,
    AllowedDisclosureHashAlgorithms = ["sha-256"]
});
builder.Services.AddTransient<SdJwtPresenter>();

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
        RateLimitPartition.GetConcurrencyLimiter(
            "profile-global",
            _ => new ConcurrencyLimiterOptions
            {
                PermitLimit = 1,
                QueueLimit = 2,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));
});

builder.Services.AddSentinelAspNetCore()
    .AddAll()
    .ConfigureAcrRanking();

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
            context.Response.ContentType = "application/problem+json";

            var traceId = context.TraceIdentifier.Replace("\"", "\\\"", StringComparison.Ordinal);
            var payload =
                $"{{\"type\":\"/errors/internal\",\"title\":\"Unexpected error\",\"detail\":\"An unexpected error occurred while processing the request.\",\"status\":500,\"traceId\":\"{traceId}\"}}";

            await context.Response.WriteAsync(payload);
        });
    });
}

app.UseForwardedHeaders();
app.UseHttpsRedirection();
app.UseRateLimiter();

app.UseAuthentication();

app.UseSentinelSecurityPipeline();

app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference("/docs");
}

const string securityPrefix = "v1";
const string documentsPrefix = "api/v1/documents";
const string financePrefix = "api/v1/finance";
const string showcasePrefix = "api/v1/showcase";

app.MapGet("/", () => TypedResults.Ok(
    new SampleInfoResponse(
        "Sentinel.Sample.MinimalApi",
        "/docs",
        new EndpointMap(
            "/healthz",
            $"/{securityPrefix}",
            $"/{documentsPrefix}",
            $"/{financePrefix}",
            $"/{showcasePrefix}")))).AllowAnonymous();

app.MapGet("/healthz", () => TypedResults.Ok(new HealthResponse("ok", DateTimeOffset.UtcNow)))
    .AllowAnonymous();

app.MapSentinelSecurity();
app.MapDocumentEndpoints(documentsPrefix);
app.MapFinanceEndpoints(financePrefix);
app.MapShowcaseEndpoints(showcasePrefix);
app.MapDocumentEndpoints("v1/documents");
app.MapShowcaseEndpoints("v1");

app.Run();

internal sealed record SampleInfoResponse(string Service, string Docs, EndpointMap Endpoints);

internal sealed record EndpointMap(string Health, string Security, string Documents, string Finance, string Showcase);

internal sealed record HealthResponse(string Status, DateTimeOffset Utc);
