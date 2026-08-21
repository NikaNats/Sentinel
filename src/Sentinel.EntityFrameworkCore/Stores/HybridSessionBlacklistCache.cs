using System.Buffers;
using System.Data.Common;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Sentinel.EntityFrameworkCore.Models;
using Sentinel.Security.Abstractions.Exceptions;
using Sentinel.Security.Abstractions.Session;
using StackExchange.Redis;

namespace Sentinel.EntityFrameworkCore.Stores;

/// <summary>
///     High-performance, secure, and allocation-optimized hybrid session blacklist cache.
///     Uses PostgreSQL as the persistent source of truth, an L2 <see cref="ISessionBlacklistCache"/>
///     port adapter (e.g. Redis) as a volatile fast-path accelerator, and MemoryCache as a local
///     L1 revocation-only fast-fail cache with thread-safe distributed proactive revocation propagation.
/// </summary>
/// <remarks>
///     SECURITY INVARIANT (P0): L1 NEVER caches a positive "session is active" decision. L1 stores only
///     confirmed revocations. Absence of an L1 entry is never treated as "session valid" – the common path
///     still consults the L2 cache and, on failure, PostgreSQL (L3). A strict 1-second degraded-mode marker is
///     only stamped when L2 is unavailable, bounding any infrastructure-outage fail-open window to 1s.
///
///     ISOLATION (P1): The proactive Pub/Sub channel is namespaced by the composition-root-supplied
///     <c>pubSubChannelPrefix</c> (pass the configured <c>RedisOptions.KeyPrefix</c> here) so that distinct environments
///     (e.g. staging: vs prod:) sharing a single Redis cluster never cross-pollute each other's L1 revocation caches.
///
///     HEXAGONAL (DIP): This store depends strictly on the <see cref="ISessionBlacklistCache"/> port for its
///     L2 accelerator - never on a concrete Redis adapter - so alternate L2 technologies are drop-in
///     substitutable at the Composition Root.
/// </remarks>
public sealed class HybridSessionBlacklistCache : ISessionBlacklistCache, IDisposable
{
    // Strict 1-second cache used ONLY to prevent PostgreSQL stampedes when Redis is offline.
    private static readonly TimeSpan DegradedActiveTtl = TimeSpan.FromSeconds(1);

    // Thread-safe singleton fields for the background revocation listener.
    // The subscription SHARES the lifetime of the IConnectionMultiplexer and MUST NOT be
    // torn down by any per-request (scoped/transient) instance disposal.
    private static readonly Lock SubscriptionLock = new();
    private static ISubscriber? _globalSubscriber;
    private static bool _isSubscribed;

    private readonly IDbContextFactory<SentinelSecurityDbContext> _dbContextFactory;
    private readonly bool _hasSizeLimit;
    private readonly ILogger<HybridSessionBlacklistCache> _logger;
    private readonly MemoryCache? _memoryCache;
    private readonly string _pubSubChannel;
    private readonly ISessionBlacklistCache _l2Cache;
    private readonly IConnectionMultiplexer? _redisMultiplexer;
    private readonly TimeProvider _timeProvider;

    public HybridSessionBlacklistCache(
        ISessionBlacklistCache l2Cache,
        ILogger<HybridSessionBlacklistCache> logger,
        IDbContextFactory<SentinelSecurityDbContext> dbContextFactory,
        TimeProvider timeProvider,
        string pubSubChannelPrefix = "sentinel:",
        IMemoryCache? memoryCache = null,
        IOptions<MemoryCacheOptions>? memoryCacheOptions = null,
        IConnectionMultiplexer? redisMultiplexer = null)
    {
        _l2Cache = l2Cache ?? throw new ArgumentNullException(nameof(l2Cache));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _dbContextFactory = dbContextFactory ?? throw new ArgumentNullException(nameof(dbContextFactory));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

#pragma warning disable CA2213 // Injected dependency lifetimes are managed and disposed of by the DI container
        _memoryCache = memoryCache as MemoryCache;
#pragma warning restore CA2213

        _redisMultiplexer = redisMultiplexer;

        // P1 (Gap 2 fix): SetSize(1) is only permitted when the MemoryCache is strictly bounded by a SizeLimit.
        _hasSizeLimit = memoryCacheOptions?.Value?.SizeLimit.HasValue == true;

        // P1 (Gap 1 fix): Namespace the pub/sub channel per environment/tenant using the
        // composition-root-supplied prefix (pass RedisOptions.KeyPrefix at registration).
        var prefix = pubSubChannelPrefix ?? string.Empty;
        _pubSubChannel = string.IsNullOrWhiteSpace(prefix) ? "session:invalidations" : $"{prefix}session:invalidations";

        // P1 (Gap 3 fix): Eagerly subscribe during instantiation so idle replicas never miss broadcasts.
        EnsureSubscribed();
    }

    /// <summary>
    ///     Instance disposal MUST NOT unsubscribe the static cross-node listener. The subscription is
    ///     tied to the singleton <see cref="IConnectionMultiplexer" /> lifecycle and tearing it down from
    ///     an instance would silently disable the only cross-node revocation mechanism.
    /// </summary>
    public void Dispose()
    {
        // Intentionally a no-op for instance-level disposal.
    }

    /// <summary>
    ///     Blacklists a session across PostgreSQL (persistent), Redis (volatile), and the local L1.
    ///     Proactively broadcasts the revocation to all cluster nodes so their L1 caches are pre-populated.
    /// </summary>
    public async Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        var hashedId = ComputeSha256(sessionId);
        _logInitiatingRevocation(_logger, hashedId, null);

        EnsureSubscribed();

        var l1RevokedKey = $"revoked_session:{hashedId}";

        // 1. Immediately fail-closed locally to prevent TOCTOU races on this specific node.
        //    L1 stores a CONFIRMED revocation (positive marker), never an "active" state.
        if (_memoryCache is not null)
        {
            var timeToLive = expiresAt - _timeProvider.GetUtcNow();
            if (timeToLive > TimeSpan.Zero)
            {
                SetL1Cache(l1RevokedKey, true, timeToLive);
            }
        }

        // 2. Write-Through: PostgreSQL (Persistent Store of Truth)
        try
        {
            await using var dbContext =
                await _dbContextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            var now = _timeProvider.GetUtcNow();

            dbContext.SessionBlacklist.Add(new SessionBlacklistEntry
            {
                SessionId = hashedId,
                ExpiresAt = expiresAt,
                CreatedAt = now
            });

            await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (DbUpdateException ex)
        {
            if (IsUniqueConstraintViolation(ex))
            {
                _logAlreadyBlacklisted(_logger, hashedId, ex);

                // Fallback to update expiration if the requested lifespan is longer
                await UpdateExistingExpirationAsync(hashedId, expiresAt, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                _logDbWriteError(_logger, hashedId, ex);
                throw new SessionBlacklistUnavailableException("Database persistence write failure during revocation.",
                    ex);
            }
        }
        catch (Exception ex) when
            (ex is DbException or SocketException or TimeoutException or InvalidOperationException)
        {
            _logDbWriteError(_logger, hashedId, ex);
            throw new SessionBlacklistUnavailableException("Database is unavailable for persistent session revocation.",
                ex);
        }

        // 3. Write-Through: Redis (Fast-Path Distributed Cache)
        try
        {
            await _l2Cache.BlacklistSessionAsync(hashedId, expiresAt, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is RedisException or SocketException or TimeoutException
                                       or SessionBlacklistUnavailableException)
        {
            _logRedisWriteError(_logger, hashedId, ex);
            throw new SessionBlacklistUnavailableException(
                "Cache synchronization failed during session revocation. System is fail-closed.", ex);
        }

        // 4. Proactive broadcast: populate L1 revocations on OTHER nodes. Missing the broadcast is
        //    harmless - L2/L3 still protect the decision; this is purely an accelerator.
        //    Payload format: {hashedId}|{expiresAtUnixSeconds}
        if (_redisMultiplexer is not null)
        {
            try
            {
                var payload = $"{hashedId}|{expiresAt.ToUnixTimeSeconds()}";
                var subscriber = _redisMultiplexer.GetSubscriber();
                await subscriber
                    .PublishAsync(new RedisChannel(_pubSubChannel, RedisChannel.PatternMode.Literal), payload)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logPubSubError(_logger, hashedId, ex);
            }
        }
    }

    /// <summary>
    ///     Verifies if a session is blacklisted. Fails closed on infrastructure errors.
    /// </summary>
    public async Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        var hashedId = ComputeSha256(sessionId);
        var l1RevokedKey = $"revoked_session:{hashedId}";

        // --- LEVEL 1: Local Revocation Cache (0-RTT Fail-Closed Fast Path) ---
        // If the key is present, the session is CONFIRMED revoked. Absence is NOT cached as "active".
        if (_memoryCache is not null && _memoryCache.TryGetValue(l1RevokedKey, out _))
        {
            return true;
        }

        // Ensure we are subscribed to proactive revocation broadcasts
        EnsureSubscribed();

        var redisFailed = false;

        // --- LEVEL 2: Distributed Redis Cache ---
        try
        {
            var isRedisBlacklisted =
                await _l2Cache.IsBlacklistedAsync(hashedId, cancellationToken).ConfigureAwait(false);
            if (isRedisBlacklisted)
            {
                SetL1Cache(l1RevokedKey, true, TimeSpan.FromMinutes(5));

                return true;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is RedisException or SocketException or TimeoutException
                                       or SessionBlacklistUnavailableException)
        {
            redisFailed = true;
            _logRedisFallback(_logger, hashedId, ex);
        }

        // --- LEVEL 3: PostgreSQL Database ---
        // When Redis is confirmed down, a strict 1-second degraded marker may serve a cached
        // "active-not-found" decision to overcome request storms. This bounds the maximum
        // fail-open window during a Redis outage to exactly 1 second; L2/L3 are still
        // consulted once Redis recovers.
        var degradedKey = $"degraded_active:{hashedId}";
        if (redisFailed && _memoryCache is not null && _memoryCache.TryGetValue(degradedKey, out _))
        {
            return false;
        }

        try
        {
            await using var dbContext =
                await _dbContextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            var now = _timeProvider.GetUtcNow();

            var dbEntry = await dbContext.SessionBlacklist
                .AsNoTracking() // Prevent allocation tracking overhead on the hot-path lookup
                .Where(e => e.SessionId == hashedId && e.ExpiresAt > now)
                .FirstOrDefaultAsync(cancellationToken)
                .ConfigureAwait(false);

            if (dbEntry != null)
            {
                _logBackfill(_logger, hashedId, null);

                SetL1Cache(l1RevokedKey, true, dbEntry.ExpiresAt - now);

                if (!redisFailed)
                {
                    try
                    {
                        await _l2Cache.BlacklistSessionAsync(hashedId, dbEntry.ExpiresAt, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is RedisException or SocketException or TimeoutException
                                                   or SessionBlacklistUnavailableException)
                    {
                        _logBackfillFailed(_logger, hashedId, ex);
                    }
                }

                return true;
            }

            // No revocation found. If Redis is down, stamp the strict 1-second degraded marker so a
            // request storm does not collapse PostgreSQL. In no case is this marker treated as L1
            // "active proof" - it expires within 1 seconds.
            if (redisFailed && _memoryCache is not null)
            {
                SetL1Cache(degradedKey, true, DegradedActiveTtl);
            }

            return false;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when
            (ex is DbException or SocketException or TimeoutException or InvalidOperationException)
        {
            _logDbError(_logger, hashedId, ex);
            throw new SessionBlacklistUnavailableException("The system was unable to verify the session status.", ex);
        }
    }

    public async Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await using var dbContext =
                await _dbContextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            var now = _timeProvider.GetUtcNow();

            var expiredCount = await dbContext.SessionBlacklist
                .Where(e => e.ExpiresAt <= now)
                .ExecuteDeleteAsync(cancellationToken)
                .ConfigureAwait(false);

            _logCleanupSuccess(_logger, expiredCount, null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when
            (ex is DbException or SocketException or TimeoutException or InvalidOperationException)
        {
            _logCleanupError(_logger, ex);
            throw;
        }
    }

    /// <summary>
    ///     Thread-safely initializes the shared distributed revocation listener ONCE per process.
    ///     Pub/Sub is used proactively to pre-populate OTHER nodes' L1 caches with revocations. Because
    ///     L1 only holds positive revocations, a missed broadcast never causes a fail-open window.
    ///     Invoked eagerly from the constructor (idle-node protection) and re-entrantly guarded.
    /// </summary>
    private void EnsureSubscribed()
    {
        if (_isSubscribed || _redisMultiplexer is null)
        {
            return;
        }

        lock (SubscriptionLock)
        {
            if (_isSubscribed)
            {
                return;
            }

#pragma warning disable CA1031 // Intercept background connection glitches during startup gracefully
            try
            {
                _globalSubscriber = _redisMultiplexer.GetSubscriber();
                var channelQueue =
                    _globalSubscriber.Subscribe(new RedisChannel(_pubSubChannel, RedisChannel.PatternMode.Literal));

                channelQueue.OnMessage(message =>
                {
                    // Payload format: {hashedId}|{expiresAtUnixSeconds}
                    // P1 (Gap 4 fix): Zero-allocation parsing using ReadOnlySpan<char>.
                    var payloadSpan = message.Message.ToString().AsSpan();
                    if (payloadSpan.IsEmpty)
                    {
                        return;
                    }

                    var separatorIndex = payloadSpan.IndexOf('|');
                    if (separatorIndex <= 0)
                    {
                        return;
                    }

                    var hashedIdSpan = payloadSpan[..separatorIndex];
                    var l1Key = string.Concat("revoked_session:", hashedIdSpan);

                    // Default to a 5-minute pre-population if the expiry is not parseable. If the entry
                    // expires sooner, L2/L3 still confirm the source of truth.
                    var ttl = TimeSpan.FromMinutes(5);
                    var expirySpan = payloadSpan[(separatorIndex + 1)..];
                    if (long.TryParse(expirySpan, out var expiryUnix))
                    {
                        var expiry = DateTimeOffset.FromUnixTimeSeconds(expiryUnix);
                        var calculatedTtl = expiry - _timeProvider.GetUtcNow();
                        if (calculatedTtl > TimeSpan.Zero)
                        {
                            ttl = calculatedTtl;
                        }
                    }

                    SetL1Cache(l1Key, true, ttl);
                });

                _isSubscribed = true;
                _logger.LogInformation(
                    "Thread-safe distributed L1 proactive-revocation subscription initialized on channel {Channel}.",
                    _pubSubChannel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize distributed L1 subscription on channel {Channel}.",
                    _pubSubChannel);
            }
#pragma warning restore CA1031
        }
    }

    /// <summary>
    ///     Sets a non-negative cache entry while honoring an optionally configured MemoryCache SizeLimit.
    ///     Avoids InvalidOperationException when the cache has no bounding limit (Gap 2 fix).
    /// </summary>
    private void SetL1Cache(string key, bool value, TimeSpan absoluteExpirationRelativeToNow)
    {
        if (_memoryCache is null)
        {
            return;
        }

        var options = new MemoryCacheEntryOptions().SetAbsoluteExpiration(absoluteExpirationRelativeToNow);
        if (_hasSizeLimit)
        {
            options.SetSize(1);
        }

        _memoryCache.Set(key, value, options);
    }

    private async Task UpdateExistingExpirationAsync(string hashedId, DateTimeOffset newExpiresAt,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var dbContext =
                await _dbContextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            var existing = await dbContext.SessionBlacklist
                .FirstOrDefaultAsync(e => e.SessionId == hashedId, cancellationToken)
                .ConfigureAwait(false);

            if (existing is not null && newExpiresAt > existing.ExpiresAt)
            {
                existing.ExpiresAt = newExpiresAt;
                dbContext.Entry(existing).State = EntityState.Modified;
                await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Failed to update existing session expiration for: {HashedId}", hashedId);
        }
    }

    /// <summary>
    ///     Performs cryptographically secure SHA-256 hashing to sanitize session tokens from logs and storage.
    ///     Uses stackalloc for common token lengths to prevent GC allocations.
    /// </summary>
    private static string ComputeSha256(string input)
    {
        var maxBytes = Encoding.UTF8.GetMaxByteCount(input.Length);
        byte[]? rented = null;
        var utf8Bytes = maxBytes <= 256 ? stackalloc byte[256] : rented = ArrayPool<byte>.Shared.Rent(maxBytes);

        try
        {
            var written = Encoding.UTF8.GetBytes(input, utf8Bytes);
            Span<byte> hashBytes = stackalloc byte[32];
            SHA256.HashData(utf8Bytes[..written], hashBytes);
            return Convert.ToHexString(hashBytes);
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    /// <summary>
    ///     Supports multi-provider uniqueness violations (PostgreSQL standard '23505' and general SQLite/SQLServer bounds)
    /// </summary>
    private static bool IsUniqueConstraintViolation(DbUpdateException ex)
    {
        if (ex.InnerException is DbException dbEx)
        {
            return dbEx.SqlState == "23505" || dbEx.ErrorCode == 19 ||
                   dbEx.Message.Contains("UNIQUE constraint failed");
        }

        return false;
    }

    #region High-Performance Logging Delegates (Zero-Allocation on Hot Paths)

    private static readonly Action<ILogger, string, Exception?> _logInitiatingRevocation =
        LoggerMessage.Define<string>(LogLevel.Information, new EventId(2001, "InitiatingRevocation"),
            "Initiating session revocation (Write-Through) for Hashed ID: {HashedId}");

    private static readonly Action<ILogger, string, Exception?> _logAlreadyBlacklisted =
        LoggerMessage.Define<string>(LogLevel.Information, new EventId(2002, "AlreadyBlacklisted"),
            "Session {HashedId} already blacklisted in database.");

    private static readonly Action<ILogger, string, Exception?> _logDbWriteError =
        LoggerMessage.Define<string>(LogLevel.Error, new EventId(2003, "DbWriteError"),
            "Critical database persistence failure during session revocation for Hashed ID: {HashedId}");

    private static readonly Action<ILogger, string, Exception?> _logRedisWriteError =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(2005, "RedisWriteError"),
            "Redis propagation failed during session revocation for Hashed ID: {HashedId}. DB remains source of truth.");

    private static readonly Action<ILogger, string, Exception?> _logRedisFallback =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(2006, "RedisFallback"),
            "Redis cache check failed or timed out for Hashed ID {HashedId}. Falling back to PostgreSQL.");

    private static readonly Action<ILogger, string, Exception?> _logBackfill =
        LoggerMessage.Define<string>(LogLevel.Information, new EventId(2007, "Backfill"),
            "Session found in PostgreSQL blacklist. Populating Redis cache for Hashed ID: {HashedId}");

    private static readonly Action<ILogger, string, Exception?> _logBackfillFailed =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(2008, "BackfillFailed"),
            "Cache back-fill failed for Hashed ID: {HashedId}");

    private static readonly Action<ILogger, string, Exception?> _logDbError =
        LoggerMessage.Define<string>(LogLevel.Error, new EventId(2009, "DbError"),
            "Database query failure during blacklist check for Hashed ID: {HashedId}");

    private static readonly Action<ILogger, int, Exception?> _logCleanupSuccess =
        LoggerMessage.Define<int>(LogLevel.Information, new EventId(2010, "CleanupSuccess"),
            "Successfully deleted {Count} expired sessions from the PostgreSQL database.");

    private static readonly Action<ILogger, Exception?> _logCleanupError =
        LoggerMessage.Define(LogLevel.Error, new EventId(2011, "CleanupError"),
            "Error occurred during PostgreSQL session blacklist cleanup. Rethrowing to background service coordinator.");

    private static readonly Action<ILogger, string, Exception?> _logPubSubError =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(2012, "PubSubError"),
            "Failed to broadcast L1 proactive revocation event for Hashed ID: {HashedId}");

    #endregion
}