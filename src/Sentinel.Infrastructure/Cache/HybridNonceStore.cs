using System.Threading;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Telemetry;
using StackExchange.Redis;

namespace Sentinel.Infrastructure.Cache;

public sealed class HybridNonceStore(
    IServiceProvider serviceProvider,
    IMemoryCache memoryCache,
    IOptions<RedisOptions> redisOptions,
    ILogger<HybridNonceStore> logger) : IDpopNonceStore
{
    private int degradedAlertRaised;

    public async Task<string?> GetNonceAsync(string thumbprint, CancellationToken ct)
    {
        var key = GetKey(thumbprint);
        var redisDb = TryResolveRedisDatabase();
        if (redisDb is not null)
        {
            try
            {
                var nonce = await redisDb.StringGetAsync(key);
                return nonce.HasValue ? nonce.ToString() : null;
            }
            catch (Exception ex)
            {
                if (!redisOptions.Value.EnableInMemFallback)
                {
                    throw new ReplayCacheUnavailableException("dpop nonce store unavailable", ex);
                }

                EmitDegradedAlert(ex, "nonce");
            }
        }
        else if (!redisOptions.Value.EnableInMemFallback)
        {
            throw new ReplayCacheUnavailableException("dpop nonce store unavailable", new InvalidOperationException("Redis connection is unavailable."));
        }

        _ = ct;
        return memoryCache.TryGetValue<string>(key, out var nonceFallback) ? nonceFallback : null;
    }

    public async Task<bool> TryStoreNonceAsync(string thumbprint, string nonce, TimeSpan ttl, CancellationToken ct)
    {
        var key = GetKey(thumbprint);
        var redisDb = TryResolveRedisDatabase();
        if (redisDb is not null)
        {
            try
            {
                return await redisDb.StringSetAsync(key, nonce, ttl, When.NotExists);
            }
            catch (Exception ex)
            {
                if (!redisOptions.Value.EnableInMemFallback)
                {
                    throw new ReplayCacheUnavailableException("dpop nonce store unavailable", ex);
                }

                EmitDegradedAlert(ex, "nonce");
            }
        }
        else if (!redisOptions.Value.EnableInMemFallback)
        {
            throw new ReplayCacheUnavailableException("dpop nonce store unavailable", new InvalidOperationException("Redis connection is unavailable."));
        }

        _ = ct;

        if (memoryCache.TryGetValue(key, out _))
        {
            return false;
        }

        memoryCache.Set(key, nonce, ttl);
        return true;
    }

    public async Task<bool> ConsumeNonceIfMatchesAsync(string thumbprint, string expectedNonce, CancellationToken ct)
    {
        var key = GetKey(thumbprint);
        var redisDb = TryResolveRedisDatabase();
        if (redisDb is not null)
        {
            try
            {
                var tx = redisDb.CreateTransaction();
                tx.AddCondition(Condition.StringEqual(key, expectedNonce));
                _ = tx.KeyDeleteAsync(key);
                return await tx.ExecuteAsync();
            }
            catch (Exception ex)
            {
                if (!redisOptions.Value.EnableInMemFallback)
                {
                    throw new ReplayCacheUnavailableException("dpop nonce store unavailable", ex);
                }

                EmitDegradedAlert(ex, "nonce");
            }
        }
        else if (!redisOptions.Value.EnableInMemFallback)
        {
            throw new ReplayCacheUnavailableException("dpop nonce store unavailable", new InvalidOperationException("Redis connection is unavailable."));
        }

        _ = ct;

        if (!memoryCache.TryGetValue<string>(key, out var currentNonce)
            || !string.Equals(currentNonce, expectedNonce, StringComparison.Ordinal))
        {
            return false;
        }

        memoryCache.Remove(key);
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
            EmitDegradedAlert(ex, "nonce");
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

    private static string GetKey(string thumbprint) => $"dpop:nonce:{thumbprint}";
}
