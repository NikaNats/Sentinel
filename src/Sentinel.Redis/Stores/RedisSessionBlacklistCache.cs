namespace Sentinel.Redis.Stores;

using Sentinel.Security.Abstractions.Session;
using Sentinel.Security.Abstractions.InMemory;

/// <summary>
/// Redis-backed implementation of ISessionBlacklistCache with graceful in-memory fallback.
/// Stores sessions marked as revoked/logged out.
/// </summary>
public sealed class RedisSessionBlacklistCache : ISessionBlacklistCache
{
    private readonly IRedisConnectionProvider _provider;
    private readonly InMemorySessionBlacklistCache? _fallback;
    private readonly string _keyPrefix;
    private readonly ILogger<RedisSessionBlacklistCache> _logger;

    public RedisSessionBlacklistCache(
        IRedisConnectionProvider provider,
        RedisOptions options,
        ILogger<RedisSessionBlacklistCache> logger)
    {
        _provider = provider;
        _keyPrefix = options.KeyPrefix;
        _logger = logger;
        _fallback = options.EnableInMemoryFallback ? new InMemorySessionBlacklistCache() : null;
    }

    /// <summary>
    /// Blacklists a session (marks it as revoked/logged out).
    /// </summary>
    public async Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId, nameof(sessionId));

        try
        {
            // Just-in-time asynchronous connection resolution
            var multiplexer = await _provider.GetConnectionAsync(cancellationToken);
            var db = multiplexer.GetDatabase();

            var redisKey = $"{_keyPrefix}session:{sessionId}";
            var timeToLive = expiresAt.UtcDateTime - DateTime.UtcNow;

            await db.StringSetAsync(redisKey, "revoked", timeToLive);

            _logger.LogInformation("Session blacklisted: {SessionId}", sessionId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis unavailable for session blacklist, falling back to in-memory");

            if (_fallback != null)
            {
                await _fallback.BlacklistSessionAsync(sessionId, expiresAt, cancellationToken);
                return;
            }

            throw new SessionBlacklistUnavailableException("Redis is unavailable for session blacklist.", ex);
        }
    }

    /// <summary>
    /// Checks if a session is blacklisted (revoked).
    /// </summary>
    public async Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId, nameof(sessionId));

        try
        {
            // Just-in-time asynchronous connection resolution
            var multiplexer = await _provider.GetConnectionAsync(cancellationToken);
            var db = multiplexer.GetDatabase();

            var redisKey = $"{_keyPrefix}session:{sessionId}";
            var exists = await db.KeyExistsAsync(redisKey);

            _logger.LogInformation("Session blacklist check for: {SessionId}, blacklisted: {IsBlacklisted}", sessionId, exists);
            return exists;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis unavailable for session blacklist check, falling back to in-memory");

            if (_fallback != null)
            {
                return await _fallback.IsBlacklistedAsync(sessionId, cancellationToken);
            }

            throw new SessionBlacklistUnavailableException("Redis is unavailable for session blacklist check.", ex);
        }
    }

    /// <summary>
    /// Removes expired entries (garbage collection).
    /// In Redis, TTL expiration happens automatically.
    /// </summary>
    public async Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            // Just-in-time asynchronous connection resolution
            // (verifies connection is available without performing expensive operations)
            _ = await _provider.GetConnectionAsync(cancellationToken);

            // Redis automatically expires keys via TTL
            _logger.LogDebug("Session cleanup (no-op in Redis, TTL-based expiration)");
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis unavailable for session cleanup");

            if (_fallback != null)
            {
                await _fallback.CleanupExpiredAsync(cancellationToken);
                return;
            }

            throw new SessionBlacklistUnavailableException("Redis is unavailable for cleanup.", ex);
        }
    }
}
