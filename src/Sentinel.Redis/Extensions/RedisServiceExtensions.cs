namespace Sentinel.Redis.Extensions;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Session;
using Sentinel.Redis.Stores;
using StackExchange.Redis;

/// <summary>
/// Dependency injection extensions for Redis cache implementations.
/// </summary>
public static class RedisServiceExtensions
{
    /// <summary>
    /// Adds Redis-backed security caches (JTI replay, DPoP nonce, session blacklist) to DI.
    /// Falls back to in-memory implementations if Redis is unavailable.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <param name="configuration">Configuration section (e.g., "Sentinel:Redis").</param>
    /// <returns>Service collection for chaining.</returns>
    public static IServiceCollection AddRedisSecurityCaches(
        this IServiceCollection services,
        IConfiguration? configuration = null)
    {
        ArgumentNullException.ThrowIfNull(services, nameof(services));

        // Options
        var options = new RedisOptions();
        configuration?.Bind(options);

        // Register asynchronous Redis connection provider if configured
        if (!string.IsNullOrWhiteSpace(options.EndPoint))
        {
            services.AddSingleton<IRedisConnectionProvider, RedisConnectionProvider>();
        }

        // Register cache implementations
        services.AddSingleton(options);
        services.AddSingleton<IJtiReplayCache, RedisJtiReplayCache>();
        services.AddSingleton<IDpopNonceStore, RedisDpopNonceStore>();
        services.AddSingleton<ISessionBlacklistCache, RedisSessionBlacklistCache>();

        return services;
    }

    /// <summary>
    /// Adds Redis-backed security caches with explicit options.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <param name="configureOptions">Options configuration delegate.</param>
    /// <returns>Service collection for chaining.</returns>
    public static IServiceCollection AddRedisSecurityCaches(
        this IServiceCollection services,
        Action<RedisOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services, nameof(services));
        ArgumentNullException.ThrowIfNull(configureOptions, nameof(configureOptions));

        var options = new RedisOptions();
        configureOptions(options);

        // Register asynchronous Redis connection provider
        services.AddSingleton<IRedisConnectionProvider, RedisConnectionProvider>();

        // Register cache implementations
        services.AddSingleton(options);
        services.AddSingleton<IJtiReplayCache, RedisJtiReplayCache>();
        services.AddSingleton<IDpopNonceStore, RedisDpopNonceStore>();
        services.AddSingleton<ISessionBlacklistCache, RedisSessionBlacklistCache>();

        return services;
    }
}
