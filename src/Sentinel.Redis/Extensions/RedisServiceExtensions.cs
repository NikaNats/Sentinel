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
///     Dependency injection extensions for strict Redis-backed security cache implementations.
/// </summary>
public static class RedisServiceExtensions
{
    /// <summary>
    ///     Adds Redis-backed security caches to DI in fail-closed mode.
    /// </summary>
    public static IServiceCollection AddRedisSecurityCaches(
        this IServiceCollection services,
        IConfiguration? configuration = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var options = CreateOptions(configuration);
        return services.AddRedisSecurityCaches(options);
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

        return services.AddRedisSecurityCaches(options);
    }

    private static IServiceCollection AddRedisSecurityCaches(
        this IServiceCollection services,
        RedisOptions options)
    {
        services.AddSingleton(options);
        services.AddSingleton<IOptions<RedisOptions>>(new OptionsWrapper<RedisOptions>(options));
        services.AddSingleton<IValidateOptions<RedisOptions>, RedisOptionsValidator>();

        services.AddSingleton<IRedisConnectionProvider, RedisConnectionProvider>();
        services.AddSingleton<IJtiReplayCache, RedisJtiReplayCache>();
        services.AddSingleton<IDpopNonceStore, RedisDpopNonceStore>();

        services.AddSingleton<RedisSessionBlacklistCache>(sp =>
        {
            var provider = sp.GetRequiredService<IRedisConnectionProvider>();
            var redisOpts = sp.GetRequiredService<RedisOptions>();
            var logger = sp.GetRequiredService<ILogger<RedisSessionBlacklistCache>>();
            return new RedisSessionBlacklistCache(provider, redisOpts, logger);
        });

        services.AddSingleton<ISessionBlacklistCache>(sp => sp.GetRequiredService<RedisSessionBlacklistCache>());

        services.AddSingleton<IIdempotencyStore, RedisIdempotencyStore>();

        return services;
    }

    private static RedisOptions CreateOptions(IConfiguration? configuration)
    {
        if (configuration is null)
        {
            return new RedisOptions();
        }

        var syncTimeout = TryReadPositiveInt32(configuration["SyncTimeout"], out var configuredSyncTimeout)
            ? configuredSyncTimeout
            : 5000;

        return new RedisOptions
        {
            EndPoint = configuration["EndPoint"],
            UseSsl = TryReadBoolean(configuration["UseSsl"], out var useSsl) && useSsl,
            Password = configuration["Password"],
            SyncTimeout = syncTimeout,
            KeyPrefix = string.IsNullOrWhiteSpace(configuration["KeyPrefix"])
                ? "sentinel:"
                : configuration["KeyPrefix"]!
        };
    }

    private static bool TryReadBoolean(string? value, out bool result) => bool.TryParse(value, out result);

    private static bool TryReadPositiveInt32(string? value, out int result) =>
        int.TryParse(value, out result) && result > 0;
}
