using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
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

namespace Sentinel.Infrastructure.DependencyInjection;

public static class InfrastructureServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructureLayer(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddStackExchangeRedisCache(options =>
        {
            options.Configuration = configuration.GetConnectionString("Redis");
        });

        services.AddSingleton<IEncryptionService, AesGcmEncryptionService>();
        services.AddSingleton<IJtiReplayCache, JtiReplayCache>();
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
                    OnCertificateValidated = _ => Task.CompletedTask
                };
            });

        return services;
    }
}
