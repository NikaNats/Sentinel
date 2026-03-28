using Microsoft.Extensions.DependencyInjection;
using Sentinel.EntityFrameworkCore.Services;
using Sentinel.EntityFrameworkCore.Stores;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Session;

namespace Sentinel.EntityFrameworkCore.Extensions;

/// <summary>
///     Dependency injection extensions for Entity Framework Core cache implementations.
/// </summary>
public static class EntityFrameworkSecurityExtensions
{
    /// <summary>
    ///     Adds Entity Framework Core security caches to the DI container.
    ///     Registers all three cache stores (JTI replay, DPoP nonce, session blacklist) and the background cleanup service.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <returns>Service collection for chaining.</returns>
    public static IServiceCollection AddEntityFrameworkSecurityCaches(
        this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Register cache store implementations
        services.AddScoped<IJtiReplayCache, EfJtiReplayCache>();
        services.AddScoped<IDpopNonceStore, EfDpopNonceStore>();
        services.AddScoped<ISessionBlacklistCache, EfSessionBlacklistCache>();

        // Register background service for periodic cleanup
        // Prevents database disk exhaustion DoS from unbounded cache growth
        services.AddHostedService<SecurityCacheCleanupService>();

        return services;
    }
}
