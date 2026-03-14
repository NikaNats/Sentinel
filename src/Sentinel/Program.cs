using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Infrastructure.Auth;
using Sentinel.Infrastructure.Cache;
using Sentinel.Infrastructure.Telemetry;
using Sentinel.Middleware;
using System.Threading.RateLimiting;

AppContext.SetSwitch("Switch.System.Security.Cryptography.UseLegacyFipsThrow", false);

if (OperatingSystem.IsLinux()
    && File.Exists("/proc/sys/crypto/fips_enabled")
    && File.ReadAllText("/proc/sys/crypto/fips_enabled").Trim() == "1")
{
    Console.WriteLine("Sentinel API is running in FIPS-enabled mode.");
}

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.ClientCertificateMode = ClientCertificateMode.DelayCertificate;
        httpsOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls13;
    });
});

builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((document, _, _) =>
    {
        if (document.Paths is null)
        {
            return Task.CompletedTask;
        }

        var dpopScheme = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "DPoP",
            BearerFormat = "JWT",
            In = ParameterLocation.Header,
            Description = "FAPI 2.0 Demonstrating Proof-of-Possession (DPoP) bound access token."
        };

        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
        document.Components.SecuritySchemes["DPoP"] = dpopScheme;

        return Task.CompletedTask;
    });
});
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();
builder.Services.AddControllers();
builder.Services.AddHttpContextAccessor();

builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis");
});

builder.Services.AddSingleton<IJtiReplayCache, JtiReplayCache>();
builder.Services.AddSingleton<ISessionBlacklistCache, SessionBlacklistCache>();
builder.Services.AddSingleton<IDpopProofValidator, DpopProofValidator>();
builder.Services.AddHttpClient<IUmaPermissionService, KeycloakUmaPermissionService>();
builder.Services.AddHttpClient<ITokenRefreshService, KeycloakTokenRefreshService>();
builder.Services.AddSingleton<ILogoutTokenValidator, LogoutTokenValidator>();
builder.Services.AddSingleton<ISecurityEventEmitter, SecurityEventEmitter>();
builder.Services.AddSingleton<IAuthorizationHandler, AcrAuthorizationHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, ScopeAuthorizationHandler>();
builder.Services.AddScoped<IAuthorizationHandler, UmaResourceAuthorizationHandler>();
builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, StepUpAuthorizationResultHandler>();

builder.Services.AddOpenTelemetry()
    .WithTracing(t => t
        .AddAspNetCoreInstrumentation()
        .AddSource(AuthTelemetry.SourceName))
    .WithMetrics(m => m
        .AddAspNetCoreInstrumentation()
        .AddMeter(AuthTelemetry.MeterName)
        .AddPrometheusExporter());

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        var key = httpContext.Request.Path.HasValue ? httpContext.Request.Path.Value! : "default";

        return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 100,
            Window = TimeSpan.FromMinutes(1),
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 2
        });
    });
});

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["Keycloak:Authority"];
        options.Audience = builder.Configuration["Keycloak:Audience"];
        options.MapInboundClaims = false;
        options.RequireHttpsMetadata = builder.Configuration.GetValue<bool>("Keycloak:RequireHttpsMetadata", true);
        options.RefreshOnIssuerKeyNotFound = true;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            ValidAlgorithms = ["PS256", "ES256"],
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            NameClaimType = "sub",
            RoleClaimType = "realm_access.roles"
        };

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var authHeader = context.Request.Headers.Authorization.ToString();
                if (!string.IsNullOrWhiteSpace(authHeader)
                    && authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
                {
                    context.Token = authHeader["DPoP ".Length..].Trim();
                }

                return Task.CompletedTask;
            },
            OnTokenValidated = async context =>
            {
                try
                {
                    var jti = context.Principal?.FindFirst("jti")?.Value;
                    var exp = context.Principal?.FindFirst("exp")?.Value;
                    var cache = context.HttpContext.RequestServices.GetRequiredService<IJtiReplayCache>();

                    if (string.IsNullOrWhiteSpace(jti) || string.IsNullOrWhiteSpace(exp))
                    {
                        context.Fail("Missing required token claims (jti or exp).");
                        return;
                    }

                    var isReplayed = await cache.ExistsAsync(jti, context.HttpContext.RequestAborted);
                    if (isReplayed)
                    {
                        var emitter = context.HttpContext.RequestServices.GetRequiredService<ISecurityEventEmitter>();
                        var ipHash = SecurityContextHasher.HashIp(context.HttpContext);
                        emitter.EmitTokenReplay(jti, context.Principal?.FindFirst("sub")?.Value, "sentinel-api-client", ipHash);
                        context.Fail("Token replay detected.");
                        return;
                    }

                    if (!long.TryParse(exp, out var expUnix))
                    {
                        context.Fail("Invalid exp claim.");
                        return;
                    }

                    var expTime = DateTimeOffset.FromUnixTimeSeconds(expUnix);
                    var remainingTtl = expTime - DateTimeOffset.UtcNow;
                    if (remainingTtl > TimeSpan.Zero)
                    {
                        await cache.StoreAsync(jti, remainingTtl, context.HttpContext.RequestAborted);
                    }

                    var sid = context.Principal?.FindFirst("sid")?.Value;
                    if (!string.IsNullOrWhiteSpace(sid))
                    {
                        var blacklistCache = context.HttpContext.RequestServices.GetRequiredService<ISessionBlacklistCache>();
                        var isBlacklisted = await blacklistCache.IsSessionBlacklistedAsync(sid, context.HttpContext.RequestAborted);
                        if (isBlacklisted)
                        {
                            var emitter = context.HttpContext.RequestServices.GetRequiredService<ISecurityEventEmitter>();
                            var ipHash = SecurityContextHasher.HashIp(context.HttpContext);
                            emitter.EmitAuthFailure("revoked_session_usage_attempt", context.Principal?.FindFirst("sub")?.Value, ipHash);
                            context.Fail("Session has been terminated.");
                            return;
                        }
                    }
                }
                catch (ReplayCacheUnavailableException)
                {
                    var emitter = context.HttpContext.RequestServices.GetRequiredService<ISecurityEventEmitter>();
                    emitter.EmitAuthFailure("replay_cache_unavailable", context.Principal?.FindFirst("sub")?.Value, SecurityContextHasher.HashIp(context.HttpContext));
                    context.HttpContext.Items["ReplayCacheUnavailable"] = true;
                    context.Fail("Replay cache unavailable.");
                }
            }
        };
    })
    .AddCertificate(options =>
    {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                // Workload CA validation hook for mTLS client certificates.
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .RequireClaim("acr")
        .Build();

    options.AddPolicy("ElevatedAccess", policy =>
        policy.RequireAuthenticatedUser()
            .RequireClaim("acr", "acr3")
            .RequireAssertion(context =>
            {
                var clearance = context.User.FindFirst("security_clearance")?.Value;
                return clearance is "top-secret" or "classified";
            }));

    options.AddPolicy("ReadProfile", policy =>
        policy.RequireAuthenticatedUser()
            .AddRequirements(
                new ScopeRequirement("profile"),
                new AcrRequirement("acr2")));

    options.AddPolicy("RequireAcr3", policy =>
        policy.RequireAuthenticatedUser()
            .AddRequirements(new AcrRequirement("acr3")));

    options.AddPolicy("Document:Read", policy =>
        policy.RequireAuthenticatedUser()
            .AddRequirements(new UmaResourceRequirement("document:read")));

    options.AddPolicy("Document:Delete", policy =>
        policy.RequireAuthenticatedUser()
            .AddRequirements(new UmaResourceRequirement("document:delete")));
});

var app = builder.Build();

app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseRateLimiter();
app.UseMiddleware<DpopValidationMiddleware>();
app.UseMiddleware<ReplayCacheFailureMiddleware>();

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseMiddleware<MtlsBindingMiddleware>();
app.UseMiddleware<AcrValidationMiddleware>();
app.UseAuthorization();

app.MapPrometheusScrapingEndpoint();
app.MapControllers();

app.Run();

public partial class Program;
