using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Replay;

namespace Sentinel.DPoP.Extensions;

/// <summary>
/// Dependency injection extensions for Sentinel.DPoP module.
/// </summary>
public static class DependencyInjectionExtensions
{
    /// <summary>
    /// Registers DPoP-related services in the dependency injection container.
    /// </summary>
    /// <remarks>
    /// ✅ FIX: Transient registration prevents Captive Dependency.
    /// If IJtiReplayCache is Scoped (e.g., EF Core DbContext), Singleton would capture it globally,
    /// causing DbContext concurrency exceptions in production.
    ///
    /// IMPORTANT: The consumer MUST register an implementation of <see cref="IJtiReplayCache"/>
    /// prior to calling this method. Failure to do so will result in a DI resolution exception at runtime.
    /// </remarks>
    public static IServiceCollection AddSentinelDPoP(this IServiceCollection services, IConfiguration configuration)
    {
        // ✅ FIX: Explicit Bind using Microsoft.Extensions.Configuration namespace
        services.Configure<DPoPOptions>(opts =>
        {
            var section = configuration.GetSection(DPoPOptions.SectionName);
            Microsoft.Extensions.Configuration.ConfigurationBinder.Bind(section, opts);
        });

        // ✅ FIX: Use Transient to prevent Captive Dependencies if IJtiReplayCache is Scoped
        services.AddTransient<IDpopThumbprintComputer, DpopThumbprintComputer>();
        services.AddTransient<IDpopProofValidator, DpopProofValidator>();

        return services;
    }
}
