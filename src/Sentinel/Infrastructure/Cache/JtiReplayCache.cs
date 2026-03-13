using Microsoft.Extensions.Caching.Distributed;

namespace Sentinel.Infrastructure.Cache;

public interface IJtiReplayCache
{
    ValueTask<bool> ExistsAsync(string jti, CancellationToken ct);
    Task StoreAsync(string jti, TimeSpan ttl, CancellationToken ct);
}

public sealed class ReplayCacheUnavailableException(string message, Exception innerException) : Exception(message, innerException);

public sealed class JtiReplayCache(IDistributedCache cache, ILogger<JtiReplayCache> logger) : IJtiReplayCache
{
    private static string GetKey(string jti) => $"replay:jti:{jti}";

    public async ValueTask<bool> ExistsAsync(string jti, CancellationToken ct)
    {
        try
        {
            var value = await cache.GetAsync(GetKey(jti), ct);
            return value is not null;
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Redis unavailable during jti replay check. Failing closed.");
            throw new ReplayCacheUnavailableException("jti replay cache unavailable", ex);
        }
    }

    public async Task StoreAsync(string jti, TimeSpan ttl, CancellationToken ct)
    {
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
            logger.LogCritical(ex, "Redis unavailable during jti storage. Failing closed.");
            throw new ReplayCacheUnavailableException("jti replay cache unavailable", ex);
        }
    }
}
