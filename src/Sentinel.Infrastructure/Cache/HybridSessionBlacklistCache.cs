using System.Buffers;
using System.Data.Common;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Sentinel.EntityFrameworkCore;
using Sentinel.EntityFrameworkCore.Models;
using Sentinel.Redis.Stores;
using Sentinel.Security.Abstractions.Exceptions;
using Sentinel.Security.Abstractions.Session;
using StackExchange.Redis;

namespace Sentinel.Infrastructure.Cache;

/// <summary>
///     High-performance, secure, and allocation-optimized hybrid session blacklist cache.
///     Uses PostgreSQL as the persistent source of truth, Redis as a volatile fast-path accelerator,
///     and MemoryCache as a local L1 fast active-session barrier with thread-safe distributed invalidation.
/// </summary>
public sealed class HybridSessionBlacklistCache(
    RedisSessionBlacklistCache redisCache,
    ILogger<HybridSessionBlacklistCache> logger,
    IDbContextFactory<SentinelSecurityDbContext> dbContextFactory,
    TimeProvider timeProvider,
    IMemoryCache? memoryCache = null,
    IConnectionMultiplexer? redisMultiplexer = null)
    : ISessionBlacklistCache, Application.Common.Abstractions.ISessionBlacklistCache, IDisposable
{
    private const string PubSubChannel = "session:invalidations";
    private static readonly TimeSpan L1ActiveTtl = TimeSpan.FromSeconds(30);

    // Singleton-safe subscription fields to prevent socket churning if registered as Scoped
    private static readonly Lock SubscriptionLock = new();
    private static ISubscriber? _globalSubscriber;
    private static bool _isSubscribed;

    private readonly IDbContextFactory<SentinelSecurityDbContext> _dbContextFactory =
        dbContextFactory ?? throw new ArgumentNullException(nameof(dbContextFactory));

    private readonly ILogger<HybridSessionBlacklistCache> _logger =
        logger ?? throw new ArgumentNullException(nameof(logger));

#pragma warning disable CA2213 // Injected dependency lifetimes are managed and disposed of by the DI container
    private readonly MemoryCache? _memoryCache = memoryCache as MemoryCache;
#pragma warning restore CA2213

    private readonly RedisSessionBlacklistCache _redisCache =
        redisCache ?? throw new ArgumentNullException(nameof(redisCache));

    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    public void Dispose()
    {
        // Thread-safe singleton-conscious cleanup
        lock (SubscriptionLock)
        {
            if (_isSubscribed && _globalSubscriber is not null)
            {
#pragma warning disable CA1031 // Dispose path must fail silently and never throw exceptions
                try
                {
                    _globalSubscriber.Unsubscribe(new RedisChannel(PubSubChannel, RedisChannel.PatternMode.Literal));
                }
                catch (Exception)
                {
                    // Suppress exceptions during disposal
                }
#pragma warning restore CA1031

                _isSubscribed = false;
                _globalSubscriber = null;
            }
        }
    }

    /// <summary>
    ///     Blacklists a session across both PostgreSQL (persistent) and Redis (volatile) layers.
    ///     Evicts local L1 markers on all instances via Redis Pub/Sub.
    /// </summary>
    public async Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        var hashedId = ComputeSha256(sessionId);
        _logInitiatingRevocation(_logger, hashedId, null);

        // Ensure we are thread-safely subscribed to the invalidation channel once globally
        EnsureSubscribed();

        // 1. Publish invalidation event to all cluster nodes to evict L1 cache entries
        if (redisMultiplexer is not null)
        {
            try
            {
                var subscriber = redisMultiplexer.GetSubscriber();
                await subscriber
                    .PublishAsync(new RedisChannel(PubSubChannel, RedisChannel.PatternMode.Literal), hashedId)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logPubSubError(_logger, hashedId, ex);
            }
        }

        // Local instance eviction fallback
        _memoryCache?.Remove($"active_session:{hashedId}");

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
            await _redisCache.BlacklistSessionAsync(hashedId, expiresAt, cancellationToken).ConfigureAwait(false);
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
    }

    /// <summary>
    ///     Verifies if a session is blacklisted.
    /// </summary>
    public async Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        var hashedId = ComputeSha256(sessionId);
        var l1Key = $"active_session:{hashedId}";

        // --- LEVEL 1: Local Ephemeral Active Barrier ---
        if (_memoryCache is not null && _memoryCache.TryGetValue(l1Key, out _))
        {
            return false;
        }

        // Ensure we are subscribed to distributed invalidations
        EnsureSubscribed();

        var redisFailed = false;

        // --- LEVEL 2: Distributed Redis Cache ---
        try
        {
            var isRedisBlacklisted =
                await _redisCache.IsBlacklistedAsync(hashedId, cancellationToken).ConfigureAwait(false);
            if (isRedisBlacklisted)
            {
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
        try
        {
            await using var dbContext =
                await _dbContextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            var now = _timeProvider.GetUtcNow();

            var dbEntry = await dbContext.SessionBlacklist
                .AsNoTracking() // Prevent allocation tracking overhead on hot-path lookup
                .Where(e => e.SessionId == hashedId && e.ExpiresAt > now)
                .FirstOrDefaultAsync(cancellationToken)
                .ConfigureAwait(false);

            if (dbEntry != null)
            {
                _logBackfill(_logger, hashedId, null);

                if (!redisFailed)
                {
                    try
                    {
                        await _redisCache.BlacklistSessionAsync(hashedId, dbEntry.ExpiresAt, cancellationToken)
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

            // Write to L1 active barrier to protect store from stampedes.
            if (_memoryCache is not null)
            {
                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    .SetAbsoluteExpiration(L1ActiveTtl)
                    .SetSize(1);
                _memoryCache.Set(l1Key, true, cacheEntryOptions);
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
    ///     Thread-safely initializes the shared distributed subscription once to prevent socket churning during scoped
    ///     lifecycles.
    /// </summary>
    private void EnsureSubscribed()
    {
        if (_isSubscribed || redisMultiplexer is null)
        {
            return;
        }

        lock (SubscriptionLock)
        {
            if (_isSubscribed)
            {
                return;
            }

#pragma warning disable CA1031 // Intercept background system/connection glitches during startup gracefully
            try
            {
                _globalSubscriber = redisMultiplexer.GetSubscriber();
                var channelQueue =
                    _globalSubscriber.Subscribe(new RedisChannel(PubSubChannel, RedisChannel.PatternMode.Literal));

                channelQueue.OnMessage(message =>
                {
                    var hashedId = message.Message.ToString();
                    if (!string.IsNullOrEmpty(hashedId))
                    {
                        var l1Key = $"active_session:{hashedId}";
                        _memoryCache?.Remove(l1Key);
                    }
                });

                _isSubscribed = true;
                _logger.LogInformation("Thread-safe distributed L1 invalidation sub-channel initialized.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize distributed L1 cache invalidation subscription.");
            }
#pragma warning restore CA1031
        }
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
            "Failed to broadcast L1 eviction event for Hashed ID: {HashedId}");

    #endregion

    #region Implicit/Interface Mappings

    async Task Application.Common.Abstractions.ISessionBlacklistCache.BlacklistSessionAsync(string sessionId,
        TimeSpan ttl, CancellationToken ct)
    {
        var expiresAt = _timeProvider.GetUtcNow().Add(ttl);
        await BlacklistSessionAsync(sessionId, expiresAt, ct).ConfigureAwait(false);
    }

    async ValueTask<bool> Application.Common.Abstractions.ISessionBlacklistCache.IsSessionBlacklistedAsync(
        string sessionId, CancellationToken ct) =>
        await IsBlacklistedAsync(sessionId, ct).ConfigureAwait(false);

    #endregion
}
