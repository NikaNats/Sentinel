using Microsoft.Extensions.Caching.Distributed;

namespace Sentinel.Infrastructure.Cache;

public interface ISessionBlacklistCache
{
    Task BlacklistSessionAsync(string sessionId, TimeSpan ttl, CancellationToken ct);
    ValueTask<bool> IsSessionBlacklistedAsync(string sessionId, CancellationToken ct);
}

public sealed class SessionBlacklistCache(IDistributedCache cache, ILogger<SessionBlacklistCache> logger) : ISessionBlacklistCache
{
    private static string GetKey(string sessionId) => $"blacklist:sid:{sessionId}";

    public async Task BlacklistSessionAsync(string sessionId, TimeSpan ttl, CancellationToken ct)
    {
        try
        {
            var options = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            };

            await cache.SetAsync(GetKey(sessionId), [], options, ct);
            logger.LogInformation("Session {SessionId} blacklisted for {TtlSeconds} seconds.", sessionId, ttl.TotalSeconds);
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Failed to write to Redis session blacklist. Revoked sessions may remain active.");
            throw new ReplayCacheUnavailableException("session blacklist cache unavailable", ex);
        }
    }

    public async ValueTask<bool> IsSessionBlacklistedAsync(string sessionId, CancellationToken ct)
    {
        try
        {
            var value = await cache.GetAsync(GetKey(sessionId), ct);
            return value is not null;
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Redis unavailable during session blacklist check. Failing closed.");
            throw new ReplayCacheUnavailableException("session blacklist cache unavailable", ex);
        }
    }
}
