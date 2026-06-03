using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using Microsoft.AspNetCore.RateLimiting;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Models;
using Sentinel.AspNetCore.Endpoints;
using Sentinel.AspNetCore.Extensions;
using Sentinel.Application.DependencyInjection;
using Sentinel.Infrastructure.DependencyInjection;
using Sentinel.Keycloak.Extensions;
using Sentinel.Redis.Extensions;
using Sentinel.Sample.MinimalApi;
using Sentinel.Sample.MinimalApi.Endpoints;
using Sentinel.SdJwt;
using System.Threading.RateLimiting;
using System.Net;
using Microsoft.AspNetCore.Builder;

var builder = WebApplication.CreateBuilder(args);

if (builder.Environment.IsDevelopment())
{
    builder.WebHost.ConfigureKestrel(options =>
    {
        options.ConfigureHttpsDefaults(httpsOptions =>
        {
            httpsOptions.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.DelayCertificate;
        });
    });
}

builder.Services.AddOpenApi();

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor
                               | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto;

    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();

    options.KnownIPNetworks.Add(new System.Net.IPNetwork(IPAddress.Parse("10.0.0.0"), 8));
});

builder.Services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, SampleJsonContext.Default);
});

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
        options.RequireHttpsMetadata = keycloakSection.GetValue<bool>("RequireHttpsMetadata");

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
        Service: "Sentinel.Sample.MinimalApi",
        Docs: "/docs",
        Endpoints: new EndpointMap(
            Health: "/healthz",
            Security: $"/{securityPrefix}",
            Documents: $"/{documentsPrefix}",
            Finance: $"/{financePrefix}",
            Showcase: $"/{showcasePrefix}")))).AllowAnonymous();

app.MapGet("/healthz", () => TypedResults.Ok(new HealthResponse("ok", DateTimeOffset.UtcNow)))
    .AllowAnonymous();

app.MapSentinelSecurity(securityPrefix);
app.MapDocumentEndpoints(documentsPrefix);
app.MapFinanceEndpoints(financePrefix);
app.MapShowcaseEndpoints(showcasePrefix);
app.MapDocumentEndpoints("v1/documents");
app.MapShowcaseEndpoints("v1");

app.Run();

internal sealed record SampleInfoResponse(string Service, string Docs, EndpointMap Endpoints);

internal sealed record EndpointMap(string Health, string Security, string Documents, string Finance, string Showcase);

internal sealed record HealthResponse(string Status, DateTimeOffset Utc);
