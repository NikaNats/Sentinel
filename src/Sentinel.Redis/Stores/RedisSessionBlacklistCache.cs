using Sentinel.Security.Abstractions.Session;

namespace Sentinel.Redis.Stores;

/// <summary>
///     Redis-backed implementation of ISessionBlacklistCache with Fail-Closed semantics.
///     Stores sessions marked as revoked/logged out.
///     SECURITY INVARIANT: If Redis is unavailable, all operations throw an exception.
///     Session blacklist MUST never degrade to unsafe fallback behavior.
/// </summary>
public sealed class RedisSessionBlacklistCache : ISessionBlacklistCache
{
    private readonly string _keyPrefix;
    private readonly ILogger<RedisSessionBlacklistCache> _logger;
    private readonly IRedisConnectionProvider _provider;

    public RedisSessionBlacklistCache(
        IRedisConnectionProvider provider,
        RedisOptions options,
        ILogger<RedisSessionBlacklistCache> logger)
    {
        _provider = provider;
        _keyPrefix = options.KeyPrefix;
        _logger = logger;
    }

    /// <summary>
    ///     Blacklists a session (marks it as revoked/logged out).
    ///     ✅ FIX: Matches interface exactly (DateTimeOffset expiresAt).
    ///     Internally converts to TimeSpan for Redis TTL efficiently.
    /// </summary>
    public async Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        try
        {
            // Just-in-time asynchronous connection resolution
            var multiplexer = await _provider.GetConnectionAsync(cancellationToken);
            var db = multiplexer.GetDatabase();

            var redisKey = $"{_keyPrefix}session:{sessionId}";

            // ✅ FIX: Convert DateTimeOffset to TimeSpan TTL for Redis
            var ttl = expiresAt - DateTimeOffset.UtcNow;
            if (ttl <= TimeSpan.Zero)
            {
                return; // No point blacklisting an already expired session
            }

            await db.StringSetAsync(redisKey, "revoked", ttl);

            _logger.LogTrace("Session blacklisted: {SessionId}", sessionId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Redis unavailable for session blacklist (Fail-Closed)");
            throw new SessionBlacklistUnavailableException("Redis is unavailable; session blacklist is Fail-Closed.",
                ex);
        }
    }

    /// <summary>
    ///     Checks if a session is blacklisted (revoked).
    ///     ✅ FIX: Matches interface exactly (Task&lt;bool&gt; IsBlacklistedAsync).
    /// </summary>
    public async Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        try
        {
            // Just-in-time asynchronous connection resolution
            var multiplexer = await _provider.GetConnectionAsync(cancellationToken);
            var db = multiplexer.GetDatabase();

            var redisKey = $"{_keyPrefix}session:{sessionId}";
            var exists = await db.KeyExistsAsync(redisKey);

            _logger.LogTrace("Blacklist check for {SessionId}: {IsBlacklisted}", sessionId, exists);
            return exists;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Redis unavailable for session blacklist check (Fail-Closed)");
            throw new SessionBlacklistUnavailableException(
                "Redis is unavailable for session blacklist check. System is Fail-Closed.", ex);
        }
    }

    /// <summary>
    ///     Removes expired entries (garbage collection).
    ///     In Redis, TTL expiration happens automatically.
    /// </summary>
    public async Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            // Just-in-time asynchronous connection resolution
            _ = await _provider.GetConnectionAsync(cancellationToken);

            // Redis automatically expires keys via TTL
            _logger.LogDebug("Session blacklist cleanup (no-op in Redis, TTL-based expiration)");
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Redis unavailable for session blacklist cleanup (Fail-Closed)");
            throw new SessionBlacklistUnavailableException("Redis is unavailable for cleanup. System is Fail-Closed.",
                ex);
        }
    }
}
