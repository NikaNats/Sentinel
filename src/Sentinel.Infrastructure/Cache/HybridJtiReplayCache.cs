using System.Diagnostics;
using System.Threading;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Telemetry;
using StackExchange.Redis;

namespace Sentinel.Infrastructure.Cache;

public sealed class HybridJtiReplayCache(
    IServiceProvider serviceProvider,
    IMemoryCache memoryCache,
    IOptions<RedisOptions> redisOptions,
    ILogger<HybridJtiReplayCache> logger) : IJtiReplayCache
{
    private int degradedAlertRaised;

    public async Task<bool> TryStoreIfNotExistsAsync(string jti, TimeSpan ttl, CancellationToken ct)
    {
        using var activity = AuthTelemetry.Source.StartActivity("auth.replay_cache.try_store", ActivityKind.Internal);
        activity?.SetTag("auth.jti", jti);
        activity?.SetTag("auth.ttl_seconds", ttl.TotalSeconds);

        var redisKey = GetKey(jti);
        var redisDb = TryResolveRedisDatabase();
        if (redisDb is not null)
        {
            try
            {
                var stored = await redisDb.StringSetAsync(redisKey, RedisValue.EmptyString, ttl, When.NotExists);
                activity?.SetTag("auth.replay_cache.mode", "redis");
                activity?.SetTag("auth.stored", stored);
                return stored;
            }
            catch (Exception ex)
            {
                if (!redisOptions.Value.EnableInMemFallback)
                {
                    throw new ReplayCacheUnavailableException("jti replay cache unavailable", ex);
                }

                EmitDegradedAlert(ex, "jti");
            }
        }
        else if (!redisOptions.Value.EnableInMemFallback)
        {
            throw new ReplayCacheUnavailableException("jti replay cache unavailable", new InvalidOperationException("Redis connection is unavailable."));
        }

        _ = ct;

        activity?.SetTag("auth.replay_cache.mode", "memory_fallback");
        if (memoryCache.TryGetValue(redisKey, out _))
        {
            activity?.SetTag("auth.stored", false);
            return false;
        }

        memoryCache.Set(redisKey, true, ttl);
        activity?.SetTag("auth.stored", true);
        return true;
    }

    private IDatabase? TryResolveRedisDatabase()
    {
        try
        {
            var multiplexer = serviceProvider.GetService(typeof(IConnectionMultiplexer)) as IConnectionMultiplexer;
            if (multiplexer is null || !multiplexer.IsConnected)
            {
                return null;
            }

            return multiplexer.GetDatabase();
        }
        catch (Exception ex)
        {
            EmitDegradedAlert(ex, "jti");
            return null;
        }
    }

    private void EmitDegradedAlert(Exception ex, string store)
    {
        if (Interlocked.CompareExchange(ref degradedAlertRaised, 1, 0) == 0)
        {
            AuthTelemetry.RedisDegradedModeActivations.Add(1, new KeyValuePair<string, object?>("store", store));
            logger.LogCritical(ex, "WARNING: Replay Protection is currently Node-Local");
            return;
        }

        logger.LogWarning(ex, "Redis is unavailable. Using node-local degraded mode for {Store}.", store);
    }

    private static string GetKey(string jti) => $"replay:jti:{jti}";
}
