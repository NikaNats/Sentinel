using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication;
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
using Sentinel.Infrastructure.Auth.SdJwt;
using Sentinel.Infrastructure.Auth.Ssf;
using Sentinel.Infrastructure.Cache;
using Sentinel.Infrastructure.Cryptography;
using Sentinel.Infrastructure.Notifications;
using Sentinel.Infrastructure.Telemetry;

namespace Sentinel.Infrastructure.DependencyInjection;

public static class SentinelModuleBuilderExtensions
{
    public static ISentinelSecurityBuilder AddSentinelCore(this IServiceCollection services, IConfiguration configuration)
    {
        _ = services.AddOptions<KeycloakOptions>()
            .BindConfiguration(KeycloakOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        _ = services.Configure<CaptchaOptions>(configuration.GetSection("Captcha:Turnstile"));
        _ = services.Configure<RegistrationOptions>(configuration.GetSection("Registration"));
        _ = services.Configure<ResetTokenOptions>(configuration.GetSection("PasswordReset"));
        _ = services.Configure<SocialFederationOptions>(configuration.GetSection("SocialFederation"));
        _ = services.Configure<SsfOptions>(configuration.GetSection(SsfOptions.SectionName));
        _ = services.Configure<SdJwtOptions>(configuration.GetSection(SdJwtOptions.SectionName));

        _ = services.AddSingleton<IEncryptionService, AesGcmEncryptionService>();
        _ = services.AddSingleton<IDocumentStore, InMemoryDocumentStore>();
        _ = services.AddSingleton<ILogoutTokenValidator, LogoutTokenValidator>();
        _ = services.AddSingleton<ISecurityEventEmitter, SecurityEventEmitter>();
        _ = services.AddSingleton<IResetTokenProvider, HmacResetTokenProvider>();
        _ = services.AddSingleton<TokenValidationService>();
        _ = services.AddSingleton<ISsfTokenValidator, JwtSsfTokenValidator>();
        _ = services.AddSingleton<ISsfEventProcessor, SsfEventProcessor>();
        _ = services.AddSingleton<ISdJwtVerifier, SdJwtVerifier>();

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
        _ = builder.Services.AddHttpClient<IKeycloakUserService, KeycloakAdminService>();
        _ = builder.Services.AddHttpClient<IKeycloakProfileService, KeycloakAdminService>();
        _ = builder.Services.AddHttpClient<IKeycloakFederationService, KeycloakAdminService>();
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
        var keycloakOptions = configuration.GetSection(KeycloakOptions.SectionName).Get<KeycloakOptions>() ?? new KeycloakOptions();

        var sdJwtOptions = configuration.GetSection(SdJwtOptions.SectionName).Get<SdJwtOptions>() ?? new SdJwtOptions();
        var sdJwtScheme = string.IsNullOrWhiteSpace(sdJwtOptions.AuthenticationScheme) ? "SdJwt" : sdJwtOptions.AuthenticationScheme;
        const string compositeScheme = "SentinelAuth";

        _ = builder.Services
            .AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = compositeScheme;
                options.DefaultChallengeScheme = compositeScheme;
            })
            .AddPolicyScheme(compositeScheme, compositeScheme, options =>
            {
                options.ForwardDefaultSelector = context =>
                {
                    var authorization = context.Request.Headers.Authorization.ToString();
                    if (string.IsNullOrWhiteSpace(authorization))
                    {
                        return JwtBearerDefaults.AuthenticationScheme;
                    }

                    var token = authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                        ? authorization["Bearer ".Length..].Trim()
                        : authorization.StartsWith("SD-JWT ", StringComparison.OrdinalIgnoreCase)
                            ? authorization["SD-JWT ".Length..].Trim()
                            : string.Empty;

                    return token.Contains('~', StringComparison.Ordinal)
                        ? sdJwtScheme
                        : JwtBearerDefaults.AuthenticationScheme;
                };
            })
            .AddScheme<AuthenticationSchemeOptions, SdJwtAuthenticationHandler>(sdJwtScheme, _ => { })
            .AddJwtBearer(options =>
            {
                options.Authority = keycloakOptions.Authority;
                options.Audience = keycloakOptions.Audience;
                options.MapInboundClaims = false;
                options.RequireHttpsMetadata = keycloakOptions.RequireHttpsMetadata;
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
                        if (context.Principal is null)
                        {
                            context.Fail("Missing principal.");
                            return;
                        }

                        var validationService = context.HttpContext.RequestServices.GetRequiredService<TokenValidationService>();
                        var outcome = await validationService.ValidateAsync(context.Principal, context.HttpContext, context.HttpContext.RequestAborted);
                        if (outcome.IsSuccess)
                        {
                            return;
                        }

                        if (outcome.FailureException is not null)
                        {
                            context.Fail(outcome.FailureException);
                            return;
                        }

                        context.Fail(outcome.FailureReason ?? "Token validation failed.");
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
