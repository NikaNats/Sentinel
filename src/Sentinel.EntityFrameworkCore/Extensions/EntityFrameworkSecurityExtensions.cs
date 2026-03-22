namespace Sentinel.EntityFrameworkCore.Extensions;

using Microsoft.Extensions.DependencyInjection;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Session;
using Sentinel.EntityFrameworkCore.Stores;

/// <summary>
/// Dependency injection extensions for Entity Framework Core cache implementations.
/// </summary>
public static class EntityFrameworkSecurityExtensions
{
    /// <summary>
    /// Adds Entity Framework Core security caches to the DI container.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <returns>Service collection for chaining.</returns>
    public static IServiceCollection AddEntityFrameworkSecurityCaches(
        this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services, nameof(services));

        services.AddScoped<IJtiReplayCache, EfJtiReplayCache>();
        services.AddScoped<IDpopNonceStore, EfDpopNonceStore>();
        services.AddScoped<ISessionBlacklistCache, EfSessionBlacklistCache>();

        return services;
    }
}
