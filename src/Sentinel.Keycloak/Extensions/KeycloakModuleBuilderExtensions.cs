using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Keycloak.Handlers;
using Sentinel.Keycloak.Services;
using Sentinel.Security.Abstractions.DependencyInjection;
using Sentinel.Security.Abstractions.Identity;
using ApplicationAuthRevocationService = Sentinel.Application.Auth.Interfaces.IAuthRevocationService;

namespace Sentinel.Keycloak.Extensions;

/// <summary>
///     Sentinel security builder extensions for Keycloak adapters.
/// </summary>
public static class KeycloakModuleBuilderExtensions
{
    /// <summary>
    ///     Registers Keycloak-backed identity and token services.
    /// </summary>
    public static ISentinelSecurityBuilder AddKeycloak(this ISentinelSecurityBuilder builder,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        _ = builder.Services.AddOptions<KeycloakOptions>()
            .BindConfiguration(KeycloakOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        _ = builder.Services.Configure<SocialFederationOptions>(configuration.GetSection("SocialFederation"));

        _ = builder.Services.AddSingleton<IConfigurationManager<OpenIdConnectConfiguration>>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<KeycloakOptions>>().Value;
            var authority = options.Authority.TrimEnd('/');
            var metadataEndpoint = $"{authority}/.well-known/openid-configuration";
            return new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataEndpoint,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = options.RequireHttpsMetadata });
        });

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
        _ = builder.Services.AddHttpClient<ApplicationAuthRevocationService, KeycloakAuthRevocationService>();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, SocialFederationConfiguratorHostedService>());

        return builder;
    }
}
