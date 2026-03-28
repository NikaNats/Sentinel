using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Security.Abstractions.SSF;
using Sentinel.SSF;

namespace Sentinel.Application.DependencyInjection;

/// <summary>
///     Extension methods for registering Security Signal Framework (SSF) services.
/// </summary>
public static class SsfServiceCollectionExtensions
{
    /// <summary>
    ///     Registers the Security Signal Framework (SSF) processing pipeline with high-assurance configuration.
    /// </summary>
    /// <remarks>
    ///     ✅ FIX: Strictly binds options so IOptions{SsfProcessingOptions} is resolvable.
    ///     Replaces the anti-pattern of nullable options in constructors with hard DI guarantees.
    ///     Configuration Section: "Sentinel:Ssf"
    ///     Example appsettings.json:
    ///     {
    ///     "Sentinel": {
    ///     "Ssf": {
    ///     "SessionRevocationTtlSeconds": 28800,
    ///     "MaxEventAgeSeconds": 300,
    ///     "AllowedClockSkewSeconds": 300
    ///     }
    ///     }
    ///     }
    ///     Dependencies (must be registered separately by Auth/Keycloak module):
    ///     - ISsfTokenValidator (owning module must provide based on JWKS + issuer)
    ///     - ISessionBlacklistCache (Redis implementation from Session module)
    ///     - IAuthRevocationService (implementation from Security module)
    ///     Pre-requisites:
    ///     - IConfiguration must be available
    ///     - appsettings.Ssf section must exist (or provide default values)
    ///     Usage:
    ///     services.AddSsfProcessing(configuration);
    /// </remarks>
    /// <param name="services">The service collection to register into.</param>
    /// <param name="configuration">The application configuration (typically from Host/Program.cs).</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown if services or configuration is null.</exception>
    public static IServiceCollection AddSsfProcessing(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // ✅ FIX: Strictly bind options so IOptions<SsfProcessingOptions> is resolvable
        // This replaces the anti-pattern of nullable options that get created with defaults in constructors.
        services.Configure<SsfProcessingOptions>(
            configuration.GetSection("Sentinel:Ssf"));

        // Register the high-assurance event processor
        // Scoped lifetime: Each HTTP request (webhook) gets its own instance
        services.AddScoped<ISsfEventProcessor, SsfEventProcessor>();

        return services;
    }
}
