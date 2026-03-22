using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Domain.Auth;
using Sentinel.Infrastructure.Auth;
using Sentinel.Infrastructure.Auth.Handlers;
using Sentinel.Infrastructure.Auth.Services;
using Sentinel.Infrastructure.Cache;
using Sentinel.Infrastructure.Cryptography;
using Sentinel.Infrastructure.Notifications;
using Sentinel.Infrastructure.Persistence;
using Sentinel.Infrastructure.Telemetry;
using Sentinel.Security.Abstractions.Identity;
using Sentinel.DPoP;
using Sentinel.Security.Abstractions.DPoP;

namespace Sentinel.Infrastructure.DependencyInjection;

public static class SentinelModuleBuilderExtensions
{
    public static ISentinelSecurityBuilder AddSentinelCore(this IServiceCollection services,
        IConfiguration configuration)
    {
        _ = services.AddOptions<KeycloakOptions>()
            .BindConfiguration(KeycloakOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        _ = services.Configure<CaptchaOptions>(configuration.GetSection("Captcha:Turnstile"));
        _ = services.Configure<RegistrationOptions>(configuration.GetSection("Registration"));
        _ = services.Configure<ResetTokenOptions>(configuration.GetSection("PasswordReset"));
        _ = services.Configure<SocialFederationOptions>(configuration.GetSection("SocialFederation"));

        _ = services.AddSingleton<IConfigurationManager<OpenIdConnectConfiguration>>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<KeycloakOptions>>().Value;
            var authority = options.Authority.TrimEnd('/');
            var metadataEndpoint = $"{authority}/.well-known/openid-configuration";
            return new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataEndpoint,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = options.RequireHttpsMetadata });
        });

        _ = services.AddSingleton<IEncryptionService, AesGcmEncryptionService>();
        var postgresConnectionString = configuration.GetConnectionString("Postgres");
        if (string.IsNullOrWhiteSpace(postgresConnectionString))
        {
            throw new InvalidOperationException("Connection string 'Postgres' is required for document persistence.");
        }

        _ = services.AddDbContext<SentinelDbContext>(options =>
        {
            options.UseNpgsql(postgresConnectionString);
            options.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
        });

        _ = services.AddScoped<IDocumentStore, EfCoreDocumentStore>();
        _ = services.AddSingleton<ILogoutTokenValidator, LogoutTokenValidator>();
        _ = services.AddSingleton<ISecurityEventEmitter, SecurityEventEmitter>();
        _ = services.AddSingleton<IResetTokenProvider, HmacResetTokenProvider>();
        _ = services.AddSingleton<TokenValidationService>();

        return new SentinelSecurityBuilder(services);
    }

    public static ISentinelSecurityBuilder AddDPoP(this ISentinelSecurityBuilder builder)
    {
        _ = builder.Services.AddSingleton<Sentinel.Security.Abstractions.DPoP.IDpopProofValidator, DpopProofValidator>();
        return builder;
    }

    public static ISentinelSecurityBuilder AddKeycloak(this ISentinelSecurityBuilder builder)
    {
        _ = builder.Services.AddSingleton<KeycloakAdminTokenProvider>();
        _ = builder.Services.AddTransient<KeycloakAdminAuthHandler>();
        _ = builder.Services.AddHttpClient<IUmaPermissionService, KeycloakUmaPermissionService>();
        _ = builder.Services.AddHttpClient<ITokenRefreshService, KeycloakTokenRefreshService>();
        _ = builder.Services.AddHttpClient<ITokenExchangeService, KeycloakTokenExchangeService>();
        _ = builder.Services.AddHttpClient<ICaptchaService, TurnstileService>();
        _ = builder.Services.AddHttpClient<IKeycloakUserService, KeycloakUserService>((sp, client) =>
            {
                var keycloakOptions = sp.GetRequiredService<IOptions<KeycloakOptions>>().Value;
                if (!KeycloakAuthorityEndpoints.TryBuild(keycloakOptions.Authority.TrimEnd('/'), out _,
                        out var adminRealmEndpoint))
                {
                    throw new InvalidOperationException("Keycloak authority is missing or invalid.");
                }

                client.BaseAddress = adminRealmEndpoint;
            })
            .AddHttpMessageHandler<KeycloakAdminAuthHandler>();
        _ = builder.Services.AddScoped<IIdentityRegistry>(sp =>
            (IIdentityRegistry)sp.GetRequiredService<IKeycloakUserService>());
        _ = builder.Services.AddScoped<IIdentityProvider>(sp =>
            (IIdentityProvider)sp.GetRequiredService<IKeycloakUserService>());
        _ = builder.Services.AddHttpClient<IKeycloakProfileService, KeycloakProfileService>((sp, client) =>
            {
                var keycloakOptions = sp.GetRequiredService<IOptions<KeycloakOptions>>().Value;
                if (!KeycloakAuthorityEndpoints.TryBuild(keycloakOptions.Authority.TrimEnd('/'), out _,
                        out var adminRealmEndpoint))
                {
                    throw new InvalidOperationException("Keycloak authority is missing or invalid.");
                }

                client.BaseAddress = adminRealmEndpoint;
            })
            .AddHttpMessageHandler<KeycloakAdminAuthHandler>();
        _ = builder.Services.AddHttpClient<IKeycloakFederationService, KeycloakFederationService>((sp, client) =>
            {
                var keycloakOptions = sp.GetRequiredService<IOptions<KeycloakOptions>>().Value;
                if (!KeycloakAuthorityEndpoints.TryBuild(keycloakOptions.Authority.TrimEnd('/'), out _,
                        out var adminRealmEndpoint))
                {
                    throw new InvalidOperationException("Keycloak authority is missing or invalid.");
                }

                client.BaseAddress = adminRealmEndpoint;
            })
            .AddHttpMessageHandler<KeycloakAdminAuthHandler>();
        _ = builder.Services.AddHttpClient("keycloak-admin");
        _ = builder.Services.AddHttpClient<IAuthRevocationService, KeycloakAuthRevocationService>();
        _ = builder.Services.AddHostedService<SocialFederationConfiguratorHostedService>();
        return builder;
    }

    public static ISentinelSecurityBuilder AddNotificationsModule(this ISentinelSecurityBuilder builder,
        IConfiguration configuration)
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
}
