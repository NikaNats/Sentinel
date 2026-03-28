using Microsoft.Extensions.DependencyInjection;

namespace Sentinel.SdJwt.Extensions;

/// <summary>
///     Dependency injection extensions for Selective Disclosure JWT (SD-JWT) support.
/// </summary>
public static class SdJwtServiceExtensions
{
    /// <summary>
    ///     Adds SD-JWT presentation verification services to the dependency injection container.
    /// </summary>
    /// <remarks>
    ///     Registers:
    ///     - SdJwtPresenter as a transient service
    ///     - SdJwtVerificationOptions as a singleton with default configuration
    ///     An ISdJwtTokenValidator implementation must be registered separately,
    ///     as the verification strategy depends on your token issuer (e.g., Keycloak, OIDC, etc.).
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">Optional callback to configure SdJwtVerificationOptions.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddSdJwtPresentation(
        this IServiceCollection services,
        Action<SdJwtVerificationOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Configure options
        var options = new SdJwtVerificationOptions();
        configureOptions?.Invoke(options);
        services.AddSingleton(options);

        // Register presenter
        services.AddTransient<SdJwtPresenter>();

        return services;
    }

    /// <summary>
    ///     Adds SD-JWT presentation verification with a custom token validator factory.
    /// </summary>
    /// <remarks>
    ///     This overload allows you to provide a factory function that creates ISdJwtTokenValidator instances.
    ///     Useful when the validator needs access to specific DI services.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="validatorFactory">Factory function to create ISdJwtTokenValidator instances.</param>
    /// <param name="configureOptions">Optional callback to configure SdJwtVerificationOptions.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddSdJwtPresentation(
        this IServiceCollection services,
        Func<IServiceProvider, ISdJwtTokenValidator> validatorFactory,
        Action<SdJwtVerificationOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(validatorFactory);

        // Configure options
        var options = new SdJwtVerificationOptions();
        configureOptions?.Invoke(options);
        services.AddSingleton(options);

        // Register validator factory
        services.AddTransient<ISdJwtTokenValidator>(validatorFactory);

        // Register presenter
        services.AddTransient<SdJwtPresenter>();

        return services;
    }
}
