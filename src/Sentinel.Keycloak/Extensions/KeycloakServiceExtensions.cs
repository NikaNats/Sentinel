namespace Sentinel.Keycloak.Extensions;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Keycloak.Services;

/// <summary>
/// Dependency injection extensions for Keycloak integration.
/// </summary>
public static class KeycloakServiceExtensions
{
    /// <summary>
    /// Adds Keycloak OIDC integration services to the DI container.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <param name="configuration">Configuration section (e.g., "Sentinel:Keycloak").</param>
    /// <returns>Service collection for chaining.</returns>
    public static IServiceCollection AddKeycloakIntegration(
        this IServiceCollection services,
        IConfiguration? configuration = null)
    {
        ArgumentNullException.ThrowIfNull(services, nameof(services));

        var options = new KeycloakClientOptions();
        configuration?.Bind(options);

        return AddKeycloakIntegration(services, options);
    }

    /// <summary>
    /// Adds Keycloak OIDC integration services with explicit options.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <param name="configureOptions">Options configuration delegate.</param>
    /// <returns>Service collection for chaining.</returns>
    public static IServiceCollection AddKeycloakIntegration(
        this IServiceCollection services,
        Action<KeycloakClientOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services, nameof(services));
        ArgumentNullException.ThrowIfNull(configureOptions, nameof(configureOptions));

        var options = new KeycloakClientOptions();
        configureOptions(options);

        return AddKeycloakIntegration(services, options);
    }

    /// <summary>
    /// Internal method to register Keycloak services.
    /// </summary>
    private static IServiceCollection AddKeycloakIntegration(
        this IServiceCollection services,
        KeycloakClientOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.ServerUrl) || string.IsNullOrWhiteSpace(options.Realm))
        {
            throw new InvalidOperationException(
                "Keycloak ServerUrl and Realm must be configured. " +
                "Set Sentinel:Keycloak:ServerUrl and Sentinel:Keycloak:Realm in configuration.");
        }

        services.AddSingleton(options);

        services.AddHttpClient<KeycloakConfigurationManager>();
        services.AddHttpClient<KeycloakTokenService>();
        services.AddHttpClient<KeycloakSubjectService>();

        services.AddSingleton<KeycloakConfigurationManager>();
        services.AddSingleton<KeycloakTokenService>();
        services.AddSingleton<KeycloakSubjectService>();

        return services;
    }
}
