using Microsoft.Extensions.DependencyInjection;

namespace Sentinel.RAR.Extensions;

/// <summary>
/// Dependency injection extensions for Rich Authorization Request (RAR) support.
/// </summary>
public static class RarServiceExtensions
{
    /// <summary>
    /// Adds Rich Authorization Request (RAR) validation services to the dependency injection container.
    /// </summary>
    /// <remarks>
    /// Registers:
    /// - RarExtractor as a transient service
    /// - RarValidator as a transient service
    /// - FinancialAuthorizationMatcher as a transient service
    /// - RarValidationOptions as a singleton with default configuration
    /// 
    /// This overload uses the built-in FinancialAuthorizationMatcher for financial transfers.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">Optional callback to configure RarValidationOptions.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddRarValidation(
        this IServiceCollection services,
        Action<RarValidationOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Configure options
        var options = new RarValidationOptions();
        configureOptions?.Invoke(options);
        services.AddSingleton(options);

        // Register services
        services.AddTransient<RarExtractor>();
        services.AddTransient<FinancialAuthorizationMatcher>();
        services.AddTransient<IRarValidator>(sp =>
            new RarValidator(
                sp.GetRequiredService<FinancialAuthorizationMatcher>(),
                options));

        return services;
    }

    /// <summary>
    /// Adds Rich Authorization Request (RAR) validation with a custom authorization detail matcher.
    /// </summary>
    /// <remarks>
    /// This overload allows you to provide a custom IAuthorizationDetailMatcher implementation
    /// for domain-specific authorization detail types beyond the built-in financial transfer matcher.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="matcherFactory">Factory function to create IAuthorizationDetailMatcher instances.</param>
    /// <param name="configureOptions">Optional callback to configure RarValidationOptions.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddRarValidation(
        this IServiceCollection services,
        Func<IServiceProvider, IAuthorizationDetailMatcher> matcherFactory,
        Action<RarValidationOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(matcherFactory);

        // Configure options
        var options = new RarValidationOptions();
        configureOptions?.Invoke(options);
        services.AddSingleton(options);

        // Register services
        services.AddTransient<RarExtractor>();
        services.AddTransient(matcherFactory);
        services.AddTransient<IRarValidator>(sp =>
            new RarValidator(
                sp.GetRequiredService<IAuthorizationDetailMatcher>(),
                options));

        return services;
    }
}
