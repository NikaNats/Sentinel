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
        var redisConnectionString = configuration.GetConnectionString("Redis");

        services.AddStackExchangeRedisCache(options =>
        {
            options.Configuration = redisConnectionString;
        });

        services.AddSingleton<IConnectionMultiplexer>(_ =>
        {
            if (string.IsNullOrWhiteSpace(redisConnectionString))
            {
                throw new InvalidOperationException("Redis connection string is not configured.");
            }

            var options = ConfigurationOptions.Parse(redisConnectionString);
            options.AbortOnConnectFail = false;
            options.ConnectRetry = 3;

            return ConnectionMultiplexer.Connect(options);
        });

        services.AddSingleton<IEncryptionService, AesGcmEncryptionService>();
        services.AddSingleton<IJtiReplayCache, JtiReplayCache>();
        services.AddSingleton<IDpopNonceStore, DpopNonceStore>();
        services.AddSingleton<ISessionBlacklistCache, SessionBlacklistCache>();
        services.AddSingleton<IDpopProofValidator, DpopProofValidator>();
        services.AddSingleton<ILogoutTokenValidator, LogoutTokenValidator>();
        services.AddSingleton<ISecurityEventEmitter, SecurityEventEmitter>();

        services.AddHttpClient<IUmaPermissionService, KeycloakUmaPermissionService>();
        services.AddHttpClient<ITokenRefreshService, KeycloakTokenRefreshService>();
        services.AddHttpClient<IAuthRevocationService, KeycloakAuthRevocationService>();

        services.AddOpenTelemetry()
            .WithTracing(t => t
                .AddAspNetCoreInstrumentation()
                .AddSource(AuthTelemetry.SourceName))
            .WithMetrics(m => m
                .AddAspNetCoreInstrumentation()
                .AddMeter(AuthTelemetry.MeterName)
                .AddPrometheusExporter());

        services
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

                            if (!long.TryParse(exp, out var expUnix))
                            {
                                context.Fail("Invalid exp claim.");
                                return;
                            }

                            var expTime = DateTimeOffset.FromUnixTimeSeconds(expUnix);
                            var remainingTtl = expTime - DateTimeOffset.UtcNow;
                            if (remainingTtl <= TimeSpan.Zero)
                            {
                                context.Fail("Token is already expired.");
                                return;
                            }

                            var stored = await cache.TryStoreIfNotExistsAsync(jti, remainingTtl, context.HttpContext.RequestAborted);
                            if (!stored)
                            {
                                var emitter = context.HttpContext.RequestServices.GetRequiredService<ISecurityEventEmitter>();
                                var ipHash = SecurityContextHasher.HashIp(context.HttpContext);
                                emitter.EmitTokenReplay(jti, context.Principal?.FindFirst("sub")?.Value, "sentinel-api-client", ipHash);
                                context.Fail("Token replay detected.");
                                return;
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
                        catch (ReplayCacheUnavailableException ex)
                        {
                            var emitter = context.HttpContext.RequestServices.GetRequiredService<ISecurityEventEmitter>();
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
