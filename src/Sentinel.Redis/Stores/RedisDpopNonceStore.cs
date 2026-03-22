namespace Sentinel.Redis.Stores;

using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.InMemory;

/// <summary>
/// Redis-backed implementation of IDpopNonceStore with graceful in-memory fallback.
/// Stores per-client DPoP nonces (keyed by JWK thumbprint).
/// </summary>
public sealed class RedisDpopNonceStore : IDpopNonceStore
{
    private readonly IDatabase _redis;
    private readonly InMemoryDpopNonceStore? _fallback;
    private readonly string _keyPrefix;
    private readonly ILogger<RedisDpopNonceStore> _logger;

    public RedisDpopNonceStore(
        IConnectionMultiplexer connection,
        RedisOptions options,
        ILogger<RedisDpopNonceStore> logger)
    {
        _redis = connection.GetDatabase();
        _keyPrefix = options.KeyPrefix;
        _logger = logger;
        _fallback = options.EnableInMemoryFallback ? new InMemoryDpopNonceStore() : null;
    }

    /// <summary>
    /// Retrieves the current nonce for a given client (identified by JWK thumbprint).
    /// </summary>
    public async Task<string?> GetNonceAsync(string thumbprint, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));

        try
        {
            var redisKey = $"{_keyPrefix}nonce:{thumbprint}";
            var value = await _redis.StringGetAsync(redisKey);

            _logger.LogInformation("DPoP nonce retrieved for thumbprint: {Thumbprint}", thumbprint);
            return value.IsNullOrEmpty ? null : value.ToString();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis unavailable for nonce retrieval, falling back to in-memory");

            if (_fallback != null)
            {
                return await _fallback.GetNonceAsync(thumbprint, cancellationToken);
            }

            throw new NonceStoreUnavailableException($"Redis is unavailable and in-memory fallback is disabled.", ex);
        }
    }

    /// <summary>
    /// Stores a new nonce for a client, invalidating any prior nonce.
    /// </summary>
    public async Task SetNonceAsync(string thumbprint, string nonce, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce, nameof(nonce));

        try
        {
            var redisKey = $"{_keyPrefix}nonce:{thumbprint}";
            var timeToLive = expiresAt.UtcDateTime - DateTime.UtcNow;

            await _redis.StringSetAsync(redisKey, nonce, timeToLive);

            _logger.LogInformation("DPoP nonce set for thumbprint: {Thumbprint}", thumbprint);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis unavailable for nonce storage, falling back to in-memory");

            if (_fallback != null)
            {
                await _fallback.SetNonceAsync(thumbprint, nonce, expiresAt, cancellationToken);
                return;
            }

            throw new NonceStoreUnavailableException("Redis is unavailable for nonce storage.", ex);
        }
    }

    /// <summary>
    /// Removes expired nonce entries (garbage collection).
    /// In Redis, TTL expiration happens automatically.
    /// </summary>
    public async Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            // Redis automatically expires keys via TTL
            _logger.LogDebug("Nonce cleanup (no-op in Redis, TTL-based expiration)");
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis unavailable for nonce cleanup");

            if (_fallback != null)
            {
                await _fallback.CleanupExpiredAsync(cancellationToken);
                return;
            }

            throw new NonceStoreUnavailableException("Redis is unavailable for cleanup.", ex);
        }
    }
}
