using System.Data.Common;
using System.Net.Sockets;
using Microsoft.EntityFrameworkCore;
using Sentinel.EntityFrameworkCore;
using Sentinel.EntityFrameworkCore.Models;
using Sentinel.Redis.Stores;
using Sentinel.Security.Abstractions.Exceptions;
using Sentinel.Security.Abstractions.Session;
using StackExchange.Redis;

namespace Sentinel.Infrastructure.Cache;

/// <summary>
///     High-performance, secure, and allocation-optimized hybrid session blacklist cache.
///     Uses PostgreSQL as the persistent source of truth and Redis as a volatile fast-path accelerator.
///     Protects database pools against saturation by bypassing RDBMS reads when Redis is online.
/// </summary>
public sealed class HybridSessionBlacklistCache(
    RedisSessionBlacklistCache redisCache,
    ILogger<HybridSessionBlacklistCache> logger,
    IDbContextFactory<SentinelSecurityDbContext> dbContextFactory)
    : ISessionBlacklistCache,
        Application.Common.Abstractions.ISessionBlacklistCache
{
    private readonly IDbContextFactory<SentinelSecurityDbContext> _dbContextFactory =
        dbContextFactory ?? throw new ArgumentNullException(nameof(dbContextFactory));

    private readonly ILogger<HybridSessionBlacklistCache> _logger =
        logger ?? throw new ArgumentNullException(nameof(logger));

    private readonly RedisSessionBlacklistCache _redisCache =
        redisCache ?? throw new ArgumentNullException(nameof(redisCache));

    /// <summary>
    ///     Blacklists a session across both PostgreSQL (persistent) and Redis (volatile) layers.
    ///     Optimized to insert directly to database, catching duplicate key conflicts instead of pre-querying.
    /// </summary>
    public async Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        _logInitiatingRevocation(_logger, sessionId, null);

        try
        {
            await using var dbContext =
                await _dbContextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);

            dbContext.SessionBlacklist.Add(new SessionBlacklistEntry
            {
                SessionId = sessionId,
                ExpiresAt = expiresAt,
                CreatedAt = DateTimeOffset.UtcNow
            });

            await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (DbUpdateException ex)
        {
            _logAlreadyBlacklisted(_logger, sessionId, ex);
        }
        catch (Exception ex) when
            (ex is DbException or SocketException or TimeoutException or InvalidOperationException)
        {
            _logDbWriteError(_logger, sessionId, ex);
            throw new SessionBlacklistUnavailableException(
                "Database is unavailable for persistent session revocation.", ex);
        }

        try
        {
            await _redisCache.BlacklistSessionAsync(sessionId, expiresAt, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is RedisException or SocketException or TimeoutException
                                       or SessionBlacklistUnavailableException)
        {
            _logRedisWriteError(_logger, sessionId, ex);
        }
    }

    /// <summary>
    ///     Verifies if a session is blacklisted.
    ///     High-performance: Short-circuits and avoids RDBMS hits completely if Redis returns a valid check result.
    /// </summary>
    public async Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        var redisFailed = false;

        try
        {
            var isRedisBlacklisted =
                await _redisCache.IsBlacklistedAsync(sessionId, cancellationToken).ConfigureAwait(false);

            return isRedisBlacklisted;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is RedisException or SocketException or TimeoutException
                                       or SessionBlacklistUnavailableException)
        {
            redisFailed = true;
            _logRedisFallback(_logger, sessionId, ex);
        }

        if (redisFailed)
        {
            try
            {
                await using var dbContext =
                    await _dbContextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);

                var dbEntry = await dbContext.SessionBlacklist
                    .Where(e => e.SessionId == sessionId && e.ExpiresAt > DateTimeOffset.UtcNow)
                    .FirstOrDefaultAsync(cancellationToken)
                    .ConfigureAwait(false);

                if (dbEntry != null)
                {
                    _logBackfill(_logger, sessionId, null);

                    try
                    {
                        await _redisCache.BlacklistSessionAsync(sessionId, dbEntry.ExpiresAt, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is RedisException or SocketException or TimeoutException
                                                   or SessionBlacklistUnavailableException)
                    {
                        _logBackfillFailed(_logger, sessionId, ex);
                    }

                    return true;
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex) when (ex is DbException or SocketException or TimeoutException
                                           or InvalidOperationException)
            {
                _logDbError(_logger, sessionId, ex);
                throw new SessionBlacklistUnavailableException(
                    "The system was unable to verify the session status.", ex);
            }
        }

        return false;
    }

    /// <summary>
    ///     Performs garbage collection on expired session entries inside PostgreSQL database.
    /// </summary>
    public async Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await using var dbContext =
                await _dbContextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            var expiredCount = await dbContext.SessionBlacklist
                .Where(e => e.ExpiresAt <= DateTimeOffset.UtcNow)
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

    #region High-Performance Logging Delegates (Zero-Allocation on Hot Paths)

    private static readonly Action<ILogger, string, Exception?> _logInitiatingRevocation =
        LoggerMessage.Define<string>(LogLevel.Information, new EventId(2001, "InitiatingRevocation"),
            "Initiating session revocation (Write-Through): {SessionId}");

    private static readonly Action<ILogger, string, Exception?> _logAlreadyBlacklisted =
        LoggerMessage.Define<string>(LogLevel.Information, new EventId(2002, "AlreadyBlacklisted"),
            "Session {SessionId} already blacklisted in database.");

    private static readonly Action<ILogger, string, Exception?> _logDbWriteError =
        LoggerMessage.Define<string>(LogLevel.Error, new EventId(2003, "DbWriteError"),
            "Critical database persistence failure during session revocation for: {SessionId}");

    private static readonly Action<ILogger, string, Exception?> _logRedisWriteError =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(2005, "RedisWriteError"),
            "Redis propagation failed during session revocation for: {SessionId}. DB remains source of truth.");

    private static readonly Action<ILogger, string, Exception?> _logRedisFallback =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(2006, "RedisFallback"),
            "Redis cache check failed or timed out for session {SessionId}. Falling back to PostgreSQL.");

    private static readonly Action<ILogger, string, Exception?> _logBackfill =
        LoggerMessage.Define<string>(LogLevel.Information, new EventId(2007, "Backfill"),
            "Session found in PostgreSQL blacklist. Populating Redis cache for session: {SessionId}");

    private static readonly Action<ILogger, string, Exception?> _logBackfillFailed =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(2008, "BackfillFailed"),
            "Cache back-fill failed for session: {SessionId}");

    private static readonly Action<ILogger, string, Exception?> _logDbError =
        LoggerMessage.Define<string>(LogLevel.Error, new EventId(2009, "DbError"),
            "Database query failure during blacklist check for: {SessionId}");

    private static readonly Action<ILogger, int, Exception?> _logCleanupSuccess =
        LoggerMessage.Define<int>(LogLevel.Information, new EventId(2010, "CleanupSuccess"),
            "Successfully deleted {Count} expired sessions from the PostgreSQL database.");

    private static readonly Action<ILogger, Exception?> _logCleanupError =
        LoggerMessage.Define(LogLevel.Error, new EventId(2011, "CleanupError"),
            "Error occurred during PostgreSQL session blacklist cleanup. Rethrowing to background service coordinator.");

    #endregion

    #region Implicit/Interface Mappings

    async Task Application.Common.Abstractions.ISessionBlacklistCache.BlacklistSessionAsync(string sessionId,
        TimeSpan ttl, CancellationToken ct)
    {
        var expiresAt = DateTimeOffset.UtcNow.Add(ttl);
        await BlacklistSessionAsync(sessionId, expiresAt, ct).ConfigureAwait(false);
    }

    async ValueTask<bool> Application.Common.Abstractions.ISessionBlacklistCache.
        IsSessionBlacklistedAsync(string sessionId, CancellationToken ct) =>
        await IsBlacklistedAsync(sessionId, ct).ConfigureAwait(false);

    #endregion
}
