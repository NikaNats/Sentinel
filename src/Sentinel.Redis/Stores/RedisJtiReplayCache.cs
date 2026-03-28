namespace Sentinel.Redis.Stores;

using Sentinel.Security.Abstractions.Replay;

/// <summary>
/// Redis-backed implementation of IJtiReplayCache with Fail-Closed semantics.
/// Stores JWT ID (jti) claims to prevent replay attacks.
///
/// SECURITY INVARIANT: If Redis is unavailable, TryMarkUsedAsync throws an exception.
/// This ensures replay protection never degrades to unsafe fallback behavior.
/// Clients receive 503 Service Unavailable, not a false positive authorization.
/// </summary>
public sealed class RedisJtiReplayCache : IJtiReplayCache
{
    private readonly IRedisConnectionProvider _provider;
    private readonly string _keyPrefix;
    private readonly ILogger<RedisJtiReplayCache> _logger;
    private readonly TimeProvider _timeProvider;

    public RedisJtiReplayCache(
        IRedisConnectionProvider provider,
        RedisOptions options,
        ILogger<RedisJtiReplayCache> logger,
        TimeProvider? timeProvider = null)
    {
        _provider = provider;
        _keyPrefix = options.KeyPrefix;
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Marks a JWT ID as used and prevents any further use.
    /// ✅ FIX: Safe TTL computation. Protect the clock-skew window with a 1-second minimum TTL to prevent negative TimeSpan exceptions.
    /// </summary>
    public async Task<bool> TryMarkUsedAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jti, nameof(jti));

        try
        {
            // Just-in-time asynchronous connection resolution
            var multiplexer = await _provider.GetConnectionAsync(cancellationToken);
            var db = multiplexer.GetDatabase();

            var redisKey = $"{_keyPrefix}jti:{jti}";

            // ✅ FIX: Safe TTL computation. Protect the clock-skew window with a 1-second minimum TTL.
            // If expiresAt is in the past (clock skew), set 1 second TTL instead of crashing on negative TimeSpan.
            var timeToLive = expiresAt - _timeProvider.GetUtcNow();
            if (timeToLive <= TimeSpan.Zero)
            {
                timeToLive = TimeSpan.FromSeconds(1);
            }

            // SET key value NX EX timeout: Set if not exists, with expiration
            var result = await db.StringSetAsync(redisKey, "1", timeToLive, When.NotExists);

            // ✅ FIX: Downgraded from Information to Trace to prevent I/O logging saturation on hot path
            _logger.LogTrace("JTI replay cache operation succeeded for jti: {Jti}", jti);
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Redis unavailable and in-memory fallback is disabled (Fail-Closed)");
            throw new ReplayCacheUnavailableException($"Redis is unavailable; replay cache check failed. System is Fail-Closed.", ex);
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
            // Just-in-time asynchronous connection resolution
            // (verifies connection is available without performing expensive operations)
            _ = await _provider.GetConnectionAsync(cancellationToken);

            // Redis automatically expires keys via TTL
            _logger.LogDebug("JTI cleanup (no-op in Redis, TTL-based expiration)");
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Redis unavailable during cleanup (Fail-Closed)");
            throw new ReplayCacheUnavailableException("Redis is unavailable for cleanup. System is Fail-Closed.", ex);
        }
    }
}
