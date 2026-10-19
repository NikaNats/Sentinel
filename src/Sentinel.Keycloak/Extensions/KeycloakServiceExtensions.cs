using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Keycloak.Services;

namespace Sentinel.Keycloak.Extensions;

/// <summary>
///     Dependency injection extensions for Keycloak integration.
/// </summary>
public static class KeycloakServiceExtensions
{
    /// <summary>
    ///     Adds Keycloak OIDC integration services to the DI container.
    /// </summary>
    /// <remarks>
    ///     ✅ FIX: Properly configures options and registers typed clients as Transient (no captive dependencies).
    /// </remarks>
    /// <param name="services">Service collection.</param>
    /// <param name="configuration">
    ///     Host configuration. <see cref="KeycloakOptions" /> is read from the <c>Keycloak</c> section of the
    ///     registered <see cref="IConfiguration" /> (fallback: <c>Sentinel:Keycloak</c>), the same section
    ///     <c>AddKeycloak</c> uses.
    /// </param>
    /// <returns>Service collection for chaining.</returns>
    public static IServiceCollection AddKeycloakIntegration(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        _ = services.AddKeycloakOptions();

        // ✅ FIX: Register Configuration Manager with typed HTTP client (not AddSingleton override)
        services.AddHttpClient<KeycloakConfigurationManager>();

        return services;
    }
}
