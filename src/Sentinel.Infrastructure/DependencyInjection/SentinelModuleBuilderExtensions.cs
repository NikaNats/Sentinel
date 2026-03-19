using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Domain.Auth;
using Sentinel.Infrastructure.Auth;
using Sentinel.Infrastructure.Cache;
using Sentinel.Infrastructure.Cryptography;
using Sentinel.Infrastructure.Notifications;
using Sentinel.Infrastructure.Telemetry;

namespace Sentinel.Infrastructure.DependencyInjection;

public static class SentinelModuleBuilderExtensions
{
    public static ISentinelSecurityBuilder AddSentinelCore(this IServiceCollection services, IConfiguration configuration)
    {
        _ = services.Configure<CaptchaOptions>(configuration.GetSection("Captcha:Turnstile"));
        _ = services.Configure<RegistrationOptions>(configuration.GetSection("Registration"));
        _ = services.Configure<ResetTokenOptions>(configuration.GetSection("PasswordReset"));
        _ = services.Configure<SocialFederationOptions>(configuration.GetSection("SocialFederation"));

        _ = services.AddSingleton<IEncryptionService, AesGcmEncryptionService>();
        _ = services.AddSingleton<IDocumentStore, InMemoryDocumentStore>();
        _ = services.AddSingleton<ILogoutTokenValidator, LogoutTokenValidator>();
        _ = services.AddSingleton<ISecurityEventEmitter, SecurityEventEmitter>();
        _ = services.AddSingleton<IResetTokenProvider, HmacResetTokenProvider>();

        return new SentinelSecurityBuilder(services);
    }

    public static ISentinelSecurityBuilder AddDPoP(this ISentinelSecurityBuilder builder)
    {
        _ = builder.Services.AddSingleton<IDpopProofValidator, DpopProofValidator>();
        return builder;
    }

    public static ISentinelSecurityBuilder AddRedisReplayCache(this ISentinelSecurityBuilder builder, IConfiguration configuration)
    {
        _ = builder.AddSecureRedis(configuration);
        _ = builder.Services.AddSingleton<ISessionBlacklistCache, SessionBlacklistCache>();
        _ = builder.Services.AddSingleton<IEmailVerificationTokenStore, EmailVerificationTokenStore>();
        return builder;
    }

    public static ISentinelSecurityBuilder AddKeycloak(this ISentinelSecurityBuilder builder)
    {
        _ = builder.Services.AddSingleton<KeycloakAdminTokenProvider>();
        _ = builder.Services.AddHttpClient<IUmaPermissionService, KeycloakUmaPermissionService>();
        _ = builder.Services.AddHttpClient<ITokenRefreshService, KeycloakTokenRefreshService>();
        _ = builder.Services.AddHttpClient<ITokenExchangeService, KeycloakTokenExchangeService>();
        _ = builder.Services.AddHttpClient<ICaptchaService, TurnstileService>();
        _ = builder.Services.AddHttpClient<IKeycloakAdminService, KeycloakAdminService>();
        _ = builder.Services.AddHttpClient("keycloak-admin");
        _ = builder.Services.AddHttpClient<IAuthRevocationService, KeycloakAuthRevocationService>();
        _ = builder.Services.AddHostedService<SocialFederationConfiguratorHostedService>();
        return builder;
    }

    public static ISentinelSecurityBuilder AddNotificationsModule(this ISentinelSecurityBuilder builder, IConfiguration configuration)
    {
        _ = builder.Services
            .AddNotifications(configuration)
            .AddSendGrid()
            .AddTwilio();

        _ = builder.Services.AddSingleton<IEmailService, LoggingEmailService>();
        return builder;
    }

    public static ISentinelSecurityBuilder AddTelemetry(this ISentinelSecurityBuilder builder)
    {
        _ = builder.Services.AddOpenTelemetry()
            .WithTracing(t => t
                .AddAspNetCoreInstrumentation()
                .AddSource(AuthTelemetry.SourceName))
            .WithMetrics(m => m
                .AddAspNetCoreInstrumentation()
                .AddMeter(AuthTelemetry.MeterName)
                .AddPrometheusExporter());

        return builder;
    }

    public static ISentinelSecurityBuilder AddJwtAndCertificateAuth(this ISentinelSecurityBuilder builder, IConfiguration configuration)
    {
        _ = builder.Services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Authority = configuration["Keycloak:Authority"];
                options.Audience = configuration["Keycloak:Audience"];
                options.MapInboundClaims = false;
                options.RequireHttpsMetadata = configuration.GetValue<bool>("Keycloak:RequireHttpsMetadata", true);
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
                        string authHeader = context.Request.Headers.Authorization.ToString();
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
                            string? jti = context.Principal?.FindFirst("jti")?.Value;
                            string? exp = context.Principal?.FindFirst("exp")?.Value;
                            IJtiReplayCache cache = context.HttpContext.RequestServices.GetRequiredService<IJtiReplayCache>();

                            if (string.IsNullOrWhiteSpace(jti) || string.IsNullOrWhiteSpace(exp))
                            {
                                context.Fail("Missing required token claims (jti or exp).");
                                return;
                            }

                            if (!long.TryParse(exp, out long expUnix))
                            {
                                context.Fail("Invalid exp claim.");
                                return;
                            }

                            DateTimeOffset expTime = DateTimeOffset.FromUnixTimeSeconds(expUnix);
                            TimeSpan remainingTtl = expTime - DateTimeOffset.UtcNow;
                            if (remainingTtl <= TimeSpan.Zero)
                            {
                                context.Fail("Token is already expired.");
                                return;
                            }

                            bool stored = await cache.TryStoreIfNotExistsAsync(jti, remainingTtl, context.HttpContext.RequestAborted);
                            if (!stored)
                            {
                                ISecurityEventEmitter emitter = context.HttpContext.RequestServices.GetRequiredService<ISecurityEventEmitter>();
                                string ipHash = SecurityContextHasher.HashIp(context.HttpContext);
                                emitter.EmitTokenReplay(jti, context.Principal?.FindFirst("sub")?.Value, "sentinel-api-client", ipHash);
                                context.Fail("Token replay detected.");
                                return;
                            }

                            string? sid = context.Principal?.FindFirst("sid")?.Value;
                            if (!string.IsNullOrWhiteSpace(sid))
                            {
                                ISessionBlacklistCache blacklistCache = context.HttpContext.RequestServices.GetRequiredService<ISessionBlacklistCache>();
                                bool isBlacklisted = await blacklistCache.IsSessionBlacklistedAsync(sid, context.HttpContext.RequestAborted);
                                if (isBlacklisted)
                                {
                                    ISecurityEventEmitter emitter = context.HttpContext.RequestServices.GetRequiredService<ISecurityEventEmitter>();
                                    string ipHash = SecurityContextHasher.HashIp(context.HttpContext);
                                    emitter.EmitAuthFailure("revoked_session_usage_attempt", context.Principal?.FindFirst("sub")?.Value, ipHash);
                                    context.Fail("Session has been terminated.");
                                    return;
                                }
                            }
                        }
                        catch (ReplayCacheUnavailableException ex)
                        {
                            ISecurityEventEmitter emitter = context.HttpContext.RequestServices.GetRequiredService<ISecurityEventEmitter>();
                            emitter.EmitAuthFailure("replay_cache_unavailable", context.Principal?.FindFirst("sub")?.Value, SecurityContextHasher.HashIp(context.HttpContext));
                            context.Fail(ex);
                        }
                    },
                    OnChallenge = async context =>
                    {
                        if (context.AuthenticateFailure is ReplayCacheUnavailableException)
                        {
                            context.HandleResponse();
                            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                            await context.Response.WriteAsJsonAsync(new ProblemDetails
                            {
                                Type = "/errors/replay-cache-unavailable",
                                Title = "Security subsystem unavailable",
                                Detail = "Token replay protection is temporarily unavailable.",
                                Status = StatusCodes.Status503ServiceUnavailable
                            });
                        }
                    }
                };
            })
            .AddCertificate(options =>
            {
                options.AllowedCertificateTypes = CertificateTypes.All;
                options.Events = new CertificateAuthenticationEvents
                {
                    OnCertificateValidated = _ => Task.CompletedTask
                };
            });

        return builder;
    }
}
