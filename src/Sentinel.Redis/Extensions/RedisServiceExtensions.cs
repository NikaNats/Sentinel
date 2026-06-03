using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sentinel.Redis.Stores;
using Sentinel.Redis.Validators;
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
    ///     Adds Redis-backed security caches to DI.
    ///     Enforces strict Fail-Closed &amp; Fail-Fast validation on startup.
    /// </summary>
    public static IServiceCollection AddRedisSecurityCaches(
        this IServiceCollection services,
        IConfiguration? configuration = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Load options using your original, secure, AOT-compatible approach
        var options = configuration != null
            ? configuration.Get<RedisOptions>() ?? new RedisOptions()
            : new RedisOptions();

        // Register raw options for store constructors
        services.AddSingleton(options);

        // IOptions bridge using OptionsWrapper (no external .Bind() package required)
        services.AddSingleton<IOptions<RedisOptions>>(new OptionsWrapper<RedisOptions>(options));

        // Register validator in DI
        services.AddSingleton<IValidateOptions<RedisOptions>, RedisOptionsValidator>();

        // Redis connection provider
        services.AddSingleton<IRedisConnectionProvider, RedisConnectionProvider>();

        // Stores
        services.AddSingleton<IJtiReplayCache, RedisJtiReplayCache>();
        services.AddSingleton<IDpopNonceStore, RedisDpopNonceStore>();
        services.AddSingleton<ISessionBlacklistCache, RedisSessionBlacklistCache>();
        services.AddSingleton<IIdempotencyStore, RedisIdempotencyStore>();

        return services;
    }

    /// <summary>
    ///     Adds Redis-backed security caches with explicit options.
    /// </summary>
    public static IServiceCollection AddRedisSecurityCaches(
        this IServiceCollection services,
        Action<RedisOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        var options = new RedisOptions();
        configureOptions(options);

        // Registration
        services.AddSingleton(options);
        services.AddSingleton<IOptions<RedisOptions>>(new OptionsWrapper<RedisOptions>(options));
        services.AddSingleton<IValidateOptions<RedisOptions>, RedisOptionsValidator>();

        // Provider and stores
        services.AddSingleton<IRedisConnectionProvider, RedisConnectionProvider>();
        services.AddSingleton<IJtiReplayCache, RedisJtiReplayCache>();
        services.AddSingleton<IDpopNonceStore, RedisDpopNonceStore>();
        services.AddSingleton<ISessionBlacklistCache, RedisSessionBlacklistCache>();
        services.AddSingleton<IIdempotencyStore, RedisIdempotencyStore>();

        return services;
    }
}
