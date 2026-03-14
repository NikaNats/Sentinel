using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Telemetry;
using StackExchange.Redis;
using System.Diagnostics;

namespace Sentinel.Infrastructure.Cache;

public sealed class JtiReplayCache(IConnectionMultiplexer redis, ILogger<JtiReplayCache> logger) : IJtiReplayCache
{
    private static string GetKey(string jti) => $"replay:jti:{jti}";
    private readonly IDatabase db = redis.GetDatabase();

    public async Task<bool> TryStoreIfNotExistsAsync(string jti, TimeSpan ttl, CancellationToken ct)
    {
        using var activity = AuthTelemetry.Source.StartActivity("auth.replay_cache.try_store", ActivityKind.Internal);
        activity?.SetTag("auth.jti", jti);
        activity?.SetTag("auth.ttl_seconds", ttl.TotalSeconds);

        try
        {
            var stored = await db.StringSetAsync(GetKey(jti), RedisValue.EmptyString, ttl, When.NotExists);
            activity?.SetTag("auth.stored", stored);
            return stored;
        }
        catch (Exception ex)
        {
            activity?.SetTag("error.type", ex.GetType().Name);
            logger.LogCritical(ex, "Redis unavailable during jti replay check/store. Failing closed.");
            throw new ReplayCacheUnavailableException("jti replay cache unavailable", ex);
        }
    }
}
