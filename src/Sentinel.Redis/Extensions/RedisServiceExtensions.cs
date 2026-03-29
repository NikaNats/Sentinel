using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Redis.Stores;
using Sentinel.Security.Abstractions.Idempotency;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Session;

namespace Sentinel.Redis.Extensions;

/// <summary>
///     Dependency injection extensions for Redis cache implementations.
/// </summary>
public static class RedisServiceExtensions
{
    /// <summary>
    ///     Adds Redis-backed security caches (JTI replay, DPoP nonce, session blacklist) to DI.
    ///     Falls back to in-memory implementations if Redis is unavailable.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <param name="configuration">Configuration section (e.g., "Sentinel:Redis").</param>
    /// <returns>Service collection for chaining.</returns>
    public static IServiceCollection AddRedisSecurityCaches(
        this IServiceCollection services,
        IConfiguration? configuration = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        // ✅ FIX (AOT): Use Get<T>() instead of Bind() for Native AOT compatibility
        // ConfigurationBinder.Bind uses reflection which requires unreferenced code in AOT scenarios
        var options = configuration != null
            ? configuration.Get<RedisOptions>() ?? new RedisOptions()
            : new RedisOptions();

        // ALWAYS register the Redis connection provider - it has fallback to localhost:6379
        services.AddSingleton<IRedisConnectionProvider, RedisConnectionProvider>();

        // Register cache implementations
        services.AddSingleton(options);
        services.AddSingleton<IJtiReplayCache, RedisJtiReplayCache>();
        services.AddSingleton<IDpopNonceStore, RedisDpopNonceStore>();
        services.AddSingleton<ISessionBlacklistCache, RedisSessionBlacklistCache>();
        services.AddSingleton<IIdempotencyStore, RedisIdempotencyStore>();

        return services;
    }

    /// <summary>
    ///     Adds Redis-backed security caches with explicit options.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <param name="configureOptions">Options configuration delegate.</param>
    /// <returns>Service collection for chaining.</returns>
    public static IServiceCollection AddRedisSecurityCaches(
        this IServiceCollection services,
        Action<RedisOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        var options = new RedisOptions();
        configureOptions(options);

        // Register asynchronous Redis connection provider
        services.AddSingleton<IRedisConnectionProvider, RedisConnectionProvider>();

        // Register cache implementations
        services.AddSingleton(options);
        services.AddSingleton<IJtiReplayCache, RedisJtiReplayCache>();
        services.AddSingleton<IDpopNonceStore, RedisDpopNonceStore>();
        services.AddSingleton<ISessionBlacklistCache, RedisSessionBlacklistCache>();
        services.AddSingleton<IIdempotencyStore, RedisIdempotencyStore>();

        return services;
    }
}
