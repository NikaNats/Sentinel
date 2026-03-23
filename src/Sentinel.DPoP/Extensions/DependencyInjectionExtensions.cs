using Microsoft.Extensions.DependencyInjection;
using Sentinel.Security.Abstractions.DPoP;

namespace Sentinel.DPoP.Extensions;

/// <summary>
/// Dependency injection extensions for Sentinel.DPoP module.
/// </summary>
public static class DependencyInjectionExtensions
{
    /// <summary>
    /// Registers DPoP-related services in the dependency injection container.
    /// </summary>
    public static IServiceCollection AddSentinelDPoP(this IServiceCollection services)
    {
        _ = services.AddSingleton<IDpopThumbprintComputer, DpopThumbprintComputer>();
        _ = services.AddSingleton<IDpopProofValidator, DpopProofValidator>();
        return services;
    }
}
