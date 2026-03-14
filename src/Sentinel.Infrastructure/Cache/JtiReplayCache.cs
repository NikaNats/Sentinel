using Microsoft.Extensions.Caching.Distributed;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Telemetry;
using System.Diagnostics;

namespace Sentinel.Infrastructure.Cache;

public sealed class JtiReplayCache(IDistributedCache cache, ILogger<JtiReplayCache> logger) : IJtiReplayCache
{
    private static string GetKey(string jti) => $"replay:jti:{jti}";

    public async ValueTask<bool> ExistsAsync(string jti, CancellationToken ct)
    {
        using var activity = AuthTelemetry.Source.StartActivity("auth.replay_cache.exists", ActivityKind.Internal);
        activity?.SetTag("auth.jti", jti);

        try
        {
            var value = await cache.GetAsync(GetKey(jti), ct);
            activity?.SetTag("auth.cache_hit", value is not null);
            return value is not null;
        }
        catch (Exception ex)
        {
            activity?.SetTag("error.type", ex.GetType().Name);
            logger.LogCritical(ex, "Redis unavailable during jti replay check. Failing closed.");
            throw new ReplayCacheUnavailableException("jti replay cache unavailable", ex);
        }
    }

    public async Task StoreAsync(string jti, TimeSpan ttl, CancellationToken ct)
    {
        using var activity = AuthTelemetry.Source.StartActivity("auth.replay_cache.store", ActivityKind.Internal);
        activity?.SetTag("auth.jti", jti);
        activity?.SetTag("auth.ttl_seconds", ttl.TotalSeconds);

        try
        {
            var options = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            };

            await cache.SetAsync(GetKey(jti), [], options, ct);
        }
        catch (Exception ex)
        {
            activity?.SetTag("error.type", ex.GetType().Name);
            logger.LogCritical(ex, "Redis unavailable during jti storage. Failing closed.");
            throw new ReplayCacheUnavailableException("jti replay cache unavailable", ex);
        }
    }
}
