namespace Sentinel.Keycloak.Extensions;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sentinel.Keycloak.Services;

/// <summary>
/// Dependency injection extensions for Keycloak integration.
/// </summary>
public static class KeycloakServiceExtensions
{
    /// <summary>
    /// Adds Keycloak OIDC integration services to the DI container.
    /// </summary>
    /// <remarks>
    /// ✅ FIX: Properly configures options and registers typed clients as Transient (no captive dependencies).
    /// </remarks>
    /// <param name="services">Service collection.</param>
    /// <param name="configuration">Configuration section (e.g., "Keycloak").</param>
    /// <returns>Service collection for chaining.</returns>
    public static IServiceCollection AddKeycloakIntegration(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services, nameof(services));
        ArgumentNullException.ThrowIfNull(configuration, nameof(configuration));

        // ✅ FIX: Bind options from configuration using IOptions<KeycloakOptions> pattern
        services.Configure<KeycloakOptions>(configuration.GetSection(KeycloakOptions.SectionName));

        // ✅ FIX: Register Configuration Manager with typed HTTP client (not AddSingleton override)
        services.AddHttpClient<KeycloakConfigurationManager>();

        return services;
    }
}
