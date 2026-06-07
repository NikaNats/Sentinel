using AdversarialTestHost;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.AspNetCore.Extensions;
using Sentinel.Infrastructure.DependencyInjection;
using Sentinel.Redis.Extensions;
using Sentinel.SdJwt;
using Sentinel.Security.Abstractions.SSF;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxConcurrentConnections = 15000;
    options.Limits.MaxConcurrentUpgradedConnections = 15000;
    options.Limits.MaxRequestBodySize = 10 * 1024;

    options.Limits.MinRequestBodyDataRate = new MinDataRate(100, TimeSpan.FromSeconds(10));
    options.Limits.MinResponseDataRate = new MinDataRate(100, TimeSpan.FromSeconds(10));
    options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
});

builder.Services.Configure<JsonOptions>(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, TestHostJsonContext.Default);
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

        options.Authority = "https://localhost:8443/realms/sentinel";
        options.Audience = "sentinel-api";
        options.RequireHttpsMetadata = false;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            SignatureValidator = delegate(string token, TokenValidationParameters _) { return new JsonWebToken(token); }
        };
    });

builder.Services.AddAuthorizationBuilder();

builder.Services
    .AddRedisSecurityCaches(builder.Configuration.GetSection("Sentinel:Redis"))
    .AddSentinelCore(builder.Configuration)
    .AddDPoP(builder.Configuration)
    .AddTelemetry();

builder.Services.AddTransient<ISdJwtTokenValidator, SampleSdJwtTokenValidator>();
builder.Services.AddSingleton<ISsfTokenValidator, SampleSsfTokenValidator>();
builder.Services.AddScoped<IAuthRevocationService, SampleAuthRevocationService>();

builder.Services.AddSentinelAspNetCore()
    .AddAll()
    .ConfigureAcrRanking();

builder.Services.AddOpenApi();

var app = builder.Build();

app.UseAuthentication();
app.UseSentinelSecurityPipeline();
app.UseAuthorization();

app.MapOpenApi();

app.MapGet("/", () => TypedResults.Ok(new SampleInfoResponse(
        "Sentinel",
        "/openapi",
        new EndpointMap("/healthz", "/api/system/security", "/api/v1/documents", "/api/v1/finance",
            "/api/v1/showcase"))))
    .AllowAnonymous();

app.MapGet("/healthz", () => TypedResults.Ok(new HealthResponse("ok", DateTimeOffset.UtcNow))).AllowAnonymous();

app.MapPost("/api/system/security/auth/refresh", (RefreshRequest request) =>
    TypedResults.Ok(new RefreshResponse("mock-access-token", "mock-refresh-token"))).AllowAnonymous();

app.MapPost("/api/system/security/auth/change-password", (ChangePasswordRequest request) =>
    TypedResults.NoContent()).RequireAuthorization();

app.MapPost("/api/system/security/auth/logout", (RevokeRequest request) =>
    TypedResults.NoContent()).RequireAuthorization();

app.MapGet("/api/system/security/auth/sessions", () =>
    TypedResults.Ok(Array.Empty<object>())).RequireAuthorization();

app.MapDelete("/api/system/security/auth/sessions/{sessionId}", (string sessionId) =>
    TypedResults.NoContent()).RequireAuthorization();

app.MapPost("/api/system/security/auth/logout-all", () =>
    TypedResults.NoContent()).RequireAuthorization();

app.MapDelete("/api/system/security/auth/account", () =>
    TypedResults.NoContent()).RequireAuthorization();

app.MapPost("/api/system/security/auth/mfa/totp/setup", (TotpSetupRequest request) =>
    Results.StatusCode(501)).RequireAuthorization();

app.MapPost("/api/system/security/auth/mfa/totp/verify", (TotpVerifyRequest request) =>
    Results.StatusCode(501)).RequireAuthorization();

app.MapDelete("/api/system/security/auth/mfa/totp", () =>
    Results.StatusCode(501)).RequireAuthorization();

app.MapGet("/api/system/security/auth/mfa/recovery-codes", () =>
    Results.StatusCode(501)).RequireAuthorization();

app.MapPost("/api/system/security/auth/mfa/recovery-codes/regenerate", () =>
    Results.StatusCode(501)).RequireAuthorization();

app.MapPost("/api/system/security/auth/token-exchange", (TokenExchangeRequest request) =>
        TypedResults.Ok(new TokenExchangeResponse("mock-access-token", null, "Bearer", 3600, null)))
    .AllowAnonymous();

app.MapPost("/api/system/security/auth/backchannel-logout", () =>
    TypedResults.Ok()).AllowAnonymous();

app.MapPost("/api/system/security/ssf/events", () =>
    TypedResults.Accepted("/api/system/security/ssf/events")).RequireAuthorization();

app.MapGet("/api/v1/documents", () =>
    TypedResults.Ok(Array.Empty<DocumentSummaryDto>())).RequireAuthorization();

app.MapPost("/api/v1/documents", (CreateDocumentRequest request) =>
{
    var id = Guid.NewGuid().ToString();
    return TypedResults.Created($"/api/v1/documents/{id}", new DocumentSummaryDto(
        id, request.Title, request.Content.Length, DateTimeOffset.UtcNow));
}).RequireAuthorization();

app.MapGet("/api/v1/documents/{id}", (string id) =>
        id == "99999999-9999-9999-9999-999999999999"
            ? Results.NotFound()
            : Results.Ok(new DocumentDetailDto(id, "Test Document", "Preview content...", 100, DateTimeOffset.UtcNow)))
    .RequireAuthorization();

app.MapDelete("/api/v1/documents/{id}", (string id) =>
    id switch
    {
        "forbidden-id" => Results.Forbid(),
        "notfound-id" => Results.NotFound(),
        _ => Results.NoContent()
    }).RequireAuthorization();

app.MapPost("/api/v1/finance/transfer", (TransferRequest request, HttpContext context) =>
{
    var sub = context.User.FindFirst("sub")?.Value ?? "anonymous";
    return TypedResults.Ok(new TransferResponse(
        "Approved",
        request.TransactionId,
        $"Transfer of {request.Amount} {request.Currency.ToUpperInvariant()} approved for subject {sub}.",
        DateTimeOffset.UtcNow));
}).RequireAuthorization();

app.MapGet("/api/v1/showcase/security-context", (HttpContext context) =>
{
    var sub = context.User.FindFirst("sub")?.Value ?? "anonymous";
    return TypedResults.Ok(
        new SecurityContextDto(sub, "urn:sentinel:test", "mock-jkt", 0, Guid.NewGuid().ToString("N")));
}).RequireAuthorization();

app.Run();
