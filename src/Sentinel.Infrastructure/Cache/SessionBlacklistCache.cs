using Sentinel.Application.Common.Abstractions;
using StackExchange.Redis;

namespace Sentinel.Infrastructure.Cache;

public sealed class SessionBlacklistCache(IConnectionMultiplexer redis, ILogger<SessionBlacklistCache> logger) : ISessionBlacklistCache
{
    private readonly IDatabase db = redis.GetDatabase();
    private static string GetKey(string sessionId) => $"blacklist:sid:{sessionId}";

    public async Task BlacklistSessionAsync(string sessionId, TimeSpan ttl, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            await db.StringSetAsync(GetKey(sessionId), RedisValue.EmptyString, ttl, When.Always, CommandFlags.None);
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
        ct.ThrowIfCancellationRequested();

        try
        {
            return await db.KeyExistsAsync(GetKey(sessionId), CommandFlags.None);
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Redis unavailable during session blacklist check. Failing closed.");
            throw new ReplayCacheUnavailableException("session blacklist cache unavailable", ex);
        }
    }
}
