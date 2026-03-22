namespace Sentinel.Redis.Stores;

using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.InMemory;

/// <summary>
/// Redis-backed implementation of IJtiReplayCache with graceful in-memory fallback.
/// Stores JWT ID (jti) claims to prevent replay attacks.
/// </summary>
public sealed class RedisJtiReplayCache : IJtiReplayCache
{
    private readonly IDatabase _redis;
    private readonly InMemoryJtiReplayCache? _fallback;
    private readonly string _keyPrefix;
    private readonly ILogger<RedisJtiReplayCache> _logger;

    public RedisJtiReplayCache(
        IConnectionMultiplexer connection,
        RedisOptions options,
        ILogger<RedisJtiReplayCache> logger)
    {
        _redis = connection.GetDatabase();
        _keyPrefix = options.KeyPrefix;
        _logger = logger;
        _fallback = options.EnableInMemoryFallback ? new InMemoryJtiReplayCache() : null;
    }

    /// <summary>
    /// Marks a JWT ID as used and prevents any further use.
    /// </summary>
    public async Task<bool> TryMarkUsedAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jti, nameof(jti));

        try
        {
            var redisKey = $"{_keyPrefix}jti:{jti}";
            var timeToLive = expiresAt.UtcDateTime - DateTime.UtcNow;

            // SET key value NX EX timeout: Set if not exists, with expiration
            var result = await _redis.StringSetAsync(redisKey, "1", timeToLive, When.NotExists);

            _logger.LogInformation("JTI replay cache operation succeeded for jti: {Jti}", jti);
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis unavailable for jti replay check, falling back to in-memory");

            if (_fallback != null)
            {
                return await _fallback.TryMarkUsedAsync(jti, expiresAt, cancellationToken);
            }

            throw new ReplayCacheUnavailableException($"Redis is unavailable and in-memory fallback is disabled.", ex);
        }
    }

    /// <summary>
    /// Removes expired JTI entries (garbage collection).
    /// In Redis, TTL expiration happens automatically, so this is a no-op.
    /// </summary>
    public async Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            // Redis automatically expires keys via TTL
            _logger.LogDebug("JTI cleanup (no-op in Redis, TTL-based expiration)");
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis unavailable for jti cleanup");

            if (_fallback != null)
            {
                await _fallback.CleanupExpiredAsync(cancellationToken);
                return;
            }

            throw new ReplayCacheUnavailableException("Redis is unavailable for cleanup.", ex);
        }
    }
}
