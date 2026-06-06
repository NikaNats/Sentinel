using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using AdversarialTestHost;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.AspNetCore.Extensions;
using Sentinel.Infrastructure.DependencyInjection;
using Sentinel.Redis.Extensions;
using Sentinel.SdJwt;
using Sentinel.Security.Abstractions.Security;
using Sentinel.Security.Abstractions.SSF;
using TestHostJsonContext = AdversarialTestHost.TestHostJsonContext;

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

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseSentinelSecurityPipeline();
app.UseAuthorization();

app.MapGet("/healthz", () => TypedResults.Ok(new HealthResponse("ok", DateTimeOffset.UtcNow))).AllowAnonymous();

app.MapPost("/v1/finance/transfer", (TransferRequest request, HttpContext context) =>
{
    var sub = context.User.FindFirst("sub")?.Value ?? "anonymous";
    return TypedResults.Ok(new TransferResponse(
        "Approved",
        request.TransactionId,
        $"Transfer of {request.Amount} {request.Currency.ToUpperInvariant()} approved for subject {sub}.",
        DateTimeOffset.UtcNow));
}).RequireAuthorization();

app.Run();
