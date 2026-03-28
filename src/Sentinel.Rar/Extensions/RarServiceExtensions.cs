using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Sentinel.RAR.Extensions;

/// <summary>
/// Extension methods for registering Rich Authorization Request (RAR) services with high-assurance configuration.
/// </summary>
public static class RarServiceExtensions
{
    /// <summary>
    /// Registers the Rich Authorization Request (RAR) validation pipeline with high-assurance configuration.
    /// </summary>
    /// <remarks>
    /// ✅ FIX: Strictly binds options so IOptions{RarValidationOptions} is resolvable.
    /// Replaces the anti-pattern of nullable options in constructors with hard DI guarantees.
    ///
    /// Configuration Section: "Sentinel:Rar"
    /// Example appsettings.json:
    /// {
    ///   "Sentinel": {
    ///     "Rar": {
    ///       "MaxAuthorizationDetailsCount": 10,
    ///       "MonetaryPrecisionTolerance": 0.01,
    ///       "CaseSensitiveComparison": true
    ///     }
    ///   }
    /// }
    ///
    /// Services Registered:
    /// - IRarExtractor (transient)
    /// - IRarValidator (transient)
    /// - IAuthorizationDetailMatcher implementations (transient)
    /// - IOptions{RarValidationOptions} (from configuration)
    ///
    /// Pre-requisites:
    /// - IConfiguration must be available
    /// - appsettings.Rar section must exist (or provide default values)
    ///
    /// Usage in Program.cs:
    /// services.AddRarValidation(builder.Configuration);
    ///
    /// RarValidator will then perform polymorphic matcher routing:
    /// - Each matcher declares its support weight for authorization detail types
    /// - RarValidator selects the highest-weight matcher for each detail type
    /// - Enables extensibility without modifying RarValidator
    /// </remarks>
    /// <param name="services">The service collection to register into.</param>
    /// <param name="configuration">The application configuration (typically from Host/Program.cs).</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown if services or configuration is null.</exception>
    public static IServiceCollection AddRarValidation(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // ✅ FIX: Use explicit lambda for options configuration binding
        services.Configure<RarValidationOptions>(opts =>
        {
            configuration.GetSection("Sentinel:Rar").Bind(opts);
        });

        // ✅ FIX: Correct interface-to-implementation mapping
        services.AddTransient<IRarExtractor, RarExtractor>();
        services.AddTransient<IRarValidator, RarValidator>();

        // ✅ FIX: Register matchers into the IEnumerable{IAuthorizationDetailMatcher} collection
        // Enables RarValidator to perform polymorphic routing based on GetSupportWeight()
        services.AddTransient<IAuthorizationDetailMatcher, FinancialAuthorizationMatcher>();

        return services;
    }
}
