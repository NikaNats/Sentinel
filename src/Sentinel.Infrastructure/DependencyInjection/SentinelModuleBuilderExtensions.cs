using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.Common.Abstractions;
using Sentinel.DPoP.Extensions;
using Sentinel.Infrastructure.Auth;
using Sentinel.Infrastructure.Auth.Handlers;
using Sentinel.Infrastructure.Auth.Services;
using Sentinel.Infrastructure.Cryptography;
using Sentinel.Infrastructure.Notifications;
using Sentinel.Keycloak;
using Sentinel.Security.Abstractions.DependencyInjection;
using Sentinel.Security.Abstractions.Identity;
using Sentinel.Security.Abstractions.Security;
using Sentinel.Security.Diagnostics;
using IAuthRevocationService = Sentinel.Application.Auth.Interfaces.IAuthRevocationService;

namespace Sentinel.Infrastructure.DependencyInjection;

// Temporary implementation until real builder exists
public sealed class SentinelSecurityBuilder(IServiceCollection services) : ISentinelSecurityBuilder
{
    public IServiceCollection Services { get; } = services;
}

public static class SentinelModuleBuilderExtensions
{
    public static ISentinelSecurityBuilder AddSentinelCore(this IServiceCollection services,
        IConfiguration configuration)
    {
        _ = services.AddOptions<KeycloakOptions>()
            .BindConfiguration(KeycloakOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        _ = services.AddOptions<CryptographyOptions>()
            .BindConfiguration(CryptographyOptions.SectionName)
            .Validate(opts =>
            {
                if (string.IsNullOrWhiteSpace(opts.ActiveKeyId))
                {
                    return false;
                }

                return opts.KeyRing.ContainsKey(opts.ActiveKeyId);
            }, "Cryptography:ActiveKeyId must reference an existing key in Cryptography:KeyRing.")
            .ValidateOnStart();

        _ = services.Configure<RegistrationOptions>(configuration.GetSection("Registration"));
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

        _ = services.AddSingleton<ILogoutTokenValidator, LogoutTokenValidator>();
        _ = services.AddSingleton<ISecurityEventEmitter, SecurityEventEmitter>();
        _ = services.AddSingleton<TokenValidationService>();

        return new SentinelSecurityBuilder(services);
    }

    public static ISentinelSecurityBuilder AddDPoP(this ISentinelSecurityBuilder builder,
        IConfiguration? configuration = null)
    {
        if (configuration != null)
        {
            _ = builder.Services.AddSentinelDPoP(configuration);
        }

        return builder;
    }

    public static ISentinelSecurityBuilder AddKeycloak(this ISentinelSecurityBuilder builder)
    {
        builder.Services.TryAddSingleton<KeycloakAdminCircuitBreakerState>();
        _ = builder.Services.AddSingleton<KeycloakAdminTokenProvider>();
        _ = builder.Services.AddTransient<KeycloakAdminCircuitBreakerHandler>();
        _ = builder.Services.AddTransient<KeycloakAdminAuthHandler>();
        _ = builder.Services.AddHttpClient<IUmaPermissionService, KeycloakUmaPermissionService>();
        _ = builder.Services.AddHttpClient<ITokenRefreshService, KeycloakTokenRefreshService>();
        _ = builder.Services.AddHttpClient<ITokenExchangeService, KeycloakTokenExchangeService>();
        _ = builder.Services.AddHttpClient<IIdentityRegistry, KeycloakUserService>((sp, client) =>
            {
                var keycloakOptions = sp.GetRequiredService<IOptions<KeycloakOptions>>().Value;
                if (!KeycloakAuthorityEndpoints.TryBuild(keycloakOptions.Authority.TrimEnd('/'), out _,
                        out var adminRealmEndpoint))
                {
                    throw new InvalidOperationException("Keycloak authority is missing or invalid.");
                }

                client.BaseAddress = adminRealmEndpoint;
            })
            .AddHttpMessageHandler<KeycloakAdminCircuitBreakerHandler>()
            .AddHttpMessageHandler<KeycloakAdminAuthHandler>();
        _ = builder.Services.AddScoped<IIdentityProvider>(sp =>
            (IIdentityProvider)sp.GetRequiredService<IIdentityRegistry>());
        _ = builder.Services.AddHttpClient<IUserProfileManager, KeycloakProfileService>((sp, client) =>
            {
                var keycloakOptions = sp.GetRequiredService<IOptions<KeycloakOptions>>().Value;
                if (!KeycloakAuthorityEndpoints.TryBuild(keycloakOptions.Authority.TrimEnd('/'), out _,
                        out var adminRealmEndpoint))
                {
                    throw new InvalidOperationException("Keycloak authority is missing or invalid.");
                }

                client.BaseAddress = adminRealmEndpoint;
            })
            .AddHttpMessageHandler<KeycloakAdminCircuitBreakerHandler>()
            .AddHttpMessageHandler<KeycloakAdminAuthHandler>();
        _ = builder.Services.AddHttpClient<IIdentityFederationProvider, KeycloakFederationService>((sp, client) =>
            {
                var keycloakOptions = sp.GetRequiredService<IOptions<KeycloakOptions>>().Value;
                if (!KeycloakAuthorityEndpoints.TryBuild(keycloakOptions.Authority.TrimEnd('/'), out _,
                        out var adminRealmEndpoint))
                {
                    throw new InvalidOperationException("Keycloak authority is missing or invalid.");
                }

                client.BaseAddress = adminRealmEndpoint;
            })
            .AddHttpMessageHandler<KeycloakAdminCircuitBreakerHandler>()
            .AddHttpMessageHandler<KeycloakAdminAuthHandler>();
        _ = builder.Services.AddHttpClient("keycloak-admin")
            .AddHttpMessageHandler<KeycloakAdminCircuitBreakerHandler>();
        _ = builder.Services.AddHttpClient<IAuthRevocationService, KeycloakAuthRevocationService>();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, SocialFederationConfiguratorHostedService>());
        return builder;
    }

    public static ISentinelSecurityBuilder AddNotificationsModule(this ISentinelSecurityBuilder builder,
        IConfiguration configuration)
    {
        _ = configuration;
        builder.Services.TryAddSingleton<INotificationService, LoggingNotificationService>();
        builder.Services.TryAddSingleton<IEmailService, LoggingEmailService>();
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
