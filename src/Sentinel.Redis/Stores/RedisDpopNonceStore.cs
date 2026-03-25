namespace Sentinel.Redis.Stores;

using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.InMemory;

/// <summary>
/// Redis-backed implementation of IDpopNonceStore with graceful in-memory fallback.
/// Stores per-client DPoP nonces (keyed by JWK thumbprint).
/// </summary>
public sealed class RedisDpopNonceStore : IDpopNonceStore
{
    // Lua script guarantees atomic compare-and-delete.
    // KEYS[1] = the Redis key for the nonce
    // ARGV[1] = the expected nonce value from the DPoP proof
    // Returns: 1 if matched and deleted, 0 if mismatch or missing
    private const string ConsumeNonceScript = @"
        if redis.call('GET', KEYS[1]) == ARGV[1] then
            redis.call('DEL', KEYS[1])
            return 1
        else
            return 0
        end";

    private readonly IRedisConnectionProvider _provider;
    private readonly InMemoryDpopNonceStore? _fallback;
    private readonly string _keyPrefix;
    private readonly ILogger<RedisDpopNonceStore> _logger;

    public RedisDpopNonceStore(
        IRedisConnectionProvider provider,
        RedisOptions options,
        ILogger<RedisDpopNonceStore> logger)
    {
        _provider = provider;
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
            // Just-in-time asynchronous connection resolution
            var multiplexer = await _provider.GetConnectionAsync(cancellationToken);
            var db = multiplexer.GetDatabase();

            var redisKey = $"{_keyPrefix}nonce:{thumbprint}";
            var value = await db.StringGetAsync(redisKey);

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
            // Just-in-time asynchronous connection resolution
            var multiplexer = await _provider.GetConnectionAsync(cancellationToken);
            var db = multiplexer.GetDatabase();

            var redisKey = $"{_keyPrefix}nonce:{thumbprint}";
            var timeToLive = expiresAt.UtcDateTime - DateTime.UtcNow;

            await db.StringSetAsync(redisKey, nonce, timeToLive);

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
            // Just-in-time asynchronous connection resolution
            // (verifies connection is available without performing expensive operations)
            _ = await _provider.GetConnectionAsync(cancellationToken);

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

    /// <summary>
    /// Atomically verifies if the current nonce matches the expected value, and if so, deletes it.
    /// Prevents TOCTOU race conditions by executing the compare-and-delete as a single Lua script.
    /// </summary>
    public async Task<bool> ConsumeNonceIfMatchesAsync(string thumbprint, string expectedNonce, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedNonce, nameof(expectedNonce));

        try
        {
            var multiplexer = await _provider.GetConnectionAsync(cancellationToken);
            var db = multiplexer.GetDatabase();
            var redisKey = $"{_keyPrefix}nonce:{thumbprint}";

            // Executes the Lua script atomically on Redis single-threaded event loop
            var result = await db.ScriptEvaluateAsync(
                ConsumeNonceScript,
                keys: new StackExchange.Redis.RedisKey[] { redisKey },
                values: new StackExchange.Redis.RedisValue[] { expectedNonce }
            );

            bool wasConsumed = (long)result == 1;

            if (wasConsumed)
            {
                _logger.LogInformation("DPoP nonce atomically consumed for thumbprint: {Thumbprint}", thumbprint);
            }
            else
            {
                _logger.LogWarning("Atomic nonce consumption failed (mismatch or expired) for thumbprint: {Thumbprint}", thumbprint);
            }

            return wasConsumed;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis unavailable for atomic nonce consumption, falling back to in-memory");

            if (_fallback != null)
            {
                return await _fallback.ConsumeNonceIfMatchesAsync(thumbprint, expectedNonce, cancellationToken);
            }

            throw new NonceStoreUnavailableException("Redis is unavailable and in-memory fallback is disabled.", ex);
        }
    }
}
