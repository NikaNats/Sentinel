using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Sentinel.Session.Extensions;

/// <summary>
/// Dependency injection extensions for session management.
/// </summary>
public static class DependencyInjectionExtensions
{
    /// <summary>
    /// Adds Sentinel session management to the service collection.
    /// Registers SessionManager, SessionManagementOptions with validation, and logging.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <param name="configure">Optional configuration action for session management options.</param>
    /// <returns>Service collection for method chaining.</returns>
    public static IServiceCollection AddSentinelSessionManagement(
        this IServiceCollection services,
        Action<SessionManagementOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Register options with validation
        var optionsBuilder = services.AddOptions<SessionManagementOptions>();

        if (configure is not null)
        {
            optionsBuilder.Configure(configure);
        }

        // ✅ Register the startup validator (fails fast on misconfiguration)
        services.AddSingleton<IValidateOptions<SessionManagementOptions>, SessionManagementOptionsValidator>();

        // Register the session manager with logging
        services.AddScoped<ISessionManager, SessionManager>();

        return services;
    }
}
