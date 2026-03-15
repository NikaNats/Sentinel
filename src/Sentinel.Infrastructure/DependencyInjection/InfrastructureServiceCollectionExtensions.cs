// Sentinel Security API - FAPI 2.0 Compliant
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Auth;
using Sentinel.Infrastructure.Cache;
using Sentinel.Infrastructure.Cryptography;
using Sentinel.Infrastructure.Telemetry;
using StackExchange.Redis;

namespace Sentinel.Infrastructure.DependencyInjection;

public static class InfrastructureServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructureLayer(this IServiceCollection services, IConfiguration configuration)
    {
        string? redisConnectionString = configuration.GetConnectionString("Redis");

        _ = services.AddStackExchangeRedisCache(options =>
        {
            options.Configuration = redisConnectionString;
        });

        _ = services.AddSingleton<IConnectionMultiplexer>(_ =>
        {
            if (string.IsNullOrWhiteSpace(redisConnectionString))
            {
                throw new InvalidOperationException("Redis connection string is not configured.");
            }

            ConfigurationOptions options = ConfigurationOptions.Parse(redisConnectionString);
            options.AbortOnConnectFail = false;
            options.ConnectRetry = 3;

            return ConnectionMultiplexer.Connect(options);
        });

        _ = services.AddSingleton<IEncryptionService, AesGcmEncryptionService>();
        _ = services.AddSingleton<IJtiReplayCache, JtiReplayCache>();
        _ = services.AddSingleton<IDpopNonceStore, DpopNonceStore>();
        _ = services.AddSingleton<ISessionBlacklistCache, SessionBlacklistCache>();
        _ = services.AddSingleton<IDpopProofValidator, DpopProofValidator>();
        _ = services.AddSingleton<ILogoutTokenValidator, LogoutTokenValidator>();
        _ = services.AddSingleton<ISecurityEventEmitter, SecurityEventEmitter>();
        _ = services.AddSingleton<KeycloakAdminTokenProvider>();

        _ = services.AddHttpClient<IUmaPermissionService, KeycloakUmaPermissionService>();
        _ = services.AddHttpClient<ITokenRefreshService, KeycloakTokenRefreshService>();
        _ = services.AddHttpClient("keycloak-admin");
        _ = services.AddHttpClient<IAuthRevocationService, KeycloakAuthRevocationService>();

        _ = services.AddOpenTelemetry()
            .WithTracing(t => t
                .AddAspNetCoreInstrumentation()
                .AddSource(AuthTelemetry.SourceName))
            .WithMetrics(m => m
                .AddAspNetCoreInstrumentation()
                .AddMeter(AuthTelemetry.MeterName)
                .AddPrometheusExporter());

        _ = services
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

        return services;
    }
}
