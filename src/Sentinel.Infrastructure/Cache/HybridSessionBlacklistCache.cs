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
///     High-assurance hybrid session blacklist cache store.
///     Combines PostgreSQL (Persistent Source of Truth) and Redis (Volatile Fast-Path)
///     using "Write-Through" and "Read-Through" patterns with concurrency protection.
/// </summary>
public sealed class HybridSessionBlacklistCache(
    RedisSessionBlacklistCache redisCache,
    ILogger<HybridSessionBlacklistCache> logger,
    IDbContextFactory<SentinelSecurityDbContext>? dbContextFactory = null)
    : ISessionBlacklistCache,
        Application.Common.Abstractions.ISessionBlacklistCache
{
    private readonly ILogger<HybridSessionBlacklistCache> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    private readonly RedisSessionBlacklistCache _redisCache = redisCache ?? throw new ArgumentNullException(nameof(redisCache));

    /// <summary>
    ///     Write-Through write: Writes data to both PostgreSQL and Redis in parallel.
    ///     Protects against concurrent unique key violations gracefully without throwing false 503 errors.
    /// </summary>
    public async Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        _logger.LogInformation("Initiating session revocation (Write-Through): {SessionId}", sessionId);

        if (dbContextFactory != null)
        {
            try
            {
                await using var dbContext = await dbContextFactory.CreateDbContextAsync(cancellationToken);

                var alreadyExists = await dbContext.SessionBlacklist
                    .AnyAsync(e => e.SessionId == sessionId, cancellationToken);

                if (!alreadyExists)
                {
                    dbContext.SessionBlacklist.Add(new SessionBlacklistEntry
                    {
                        SessionId = sessionId,
                        ExpiresAt = expiresAt,
                        CreatedAt = DateTimeOffset.UtcNow
                    });
                    await dbContext.SaveChangesAsync(cancellationToken);
                }
            }
            catch (DbUpdateException ex)
            {
                _logger.LogInformation(ex, "Session {SessionId} already blacklisted by a concurrent request.", sessionId);
            }
            catch (Exception ex) when (ex is DbException or TimeoutException or SocketException or InvalidOperationException)
            {
                _logger.LogError(ex,
                    "Critical error during session revocation in PostgreSQL. System entering Fail-Closed mode.");
                throw new SessionBlacklistUnavailableException(
                    "Database is unavailable for persistent session revocation.", ex);
            }
        }
        else
        {
            _logger.LogDebug("PostgreSQL DbContextFactory not registered. Skipping persistent write.");
        }

        try
        {
            await _redisCache.BlacklistSessionAsync(sessionId, expiresAt, cancellationToken);
        }
        catch (Exception ex) when (ex is RedisException or TimeoutException or SocketException
                                       or SessionBlacklistUnavailableException)
        {
            _logger.LogWarning(ex,
                "Redis is unavailable for propagating session revocation. Operation will fall back to PostgreSQL only.");
            if (dbContextFactory == null)
            {
                throw;
            }
        }
    }

    /// <summary>
    ///     Read-Through read: First checks Redis; on a Cache Miss, queries the database and populates the cache.
    /// </summary>
    public async Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        try
        {
            var isRedisBlacklisted = await _redisCache.IsBlacklistedAsync(sessionId, cancellationToken);
            if (isRedisBlacklisted)
            {
                return true;
            }
        }
        catch (Exception ex) when (ex is RedisException or TimeoutException or SocketException
                                       or SessionBlacklistUnavailableException)
        {
            _logger.LogWarning(ex, "Redis is unavailable during session verification. Directly querying PostgreSQL.");
            if (dbContextFactory == null)
            {
                throw;
            }
        }

        if (dbContextFactory != null)
        {
            try
            {
                await using var dbContext = await dbContextFactory.CreateDbContextAsync(cancellationToken);

                var dbEntry = await dbContext.SessionBlacklist
                    .Where(e => e.SessionId == sessionId && e.ExpiresAt > DateTimeOffset.UtcNow)
                    .FirstOrDefaultAsync(cancellationToken);

                if (dbEntry != null)
                {
                    _logger.LogInformation(
                        "Session found in PostgreSQL blacklist. Populating Redis cache for session: {SessionId}",
                        sessionId);

                    try
                    {
                        await _redisCache.BlacklistSessionAsync(sessionId, dbEntry.ExpiresAt, cancellationToken);
                    }
                    catch (Exception ex) when (ex is RedisException or TimeoutException or SocketException)
                    {
                        _logger.LogWarning(ex,
                            "Failed to synchronize Redis after reading the session from the database.");
                    }

                    return true;
                }
            }
            catch (Exception ex) when (ex is DbException or DbUpdateException or TimeoutException or SocketException
                                           or InvalidOperationException)
            {
                _logger.LogError(ex, "Critical error during session blacklist check in PostgreSQL (Fail-Closed).");
                throw new SessionBlacklistUnavailableException("The system was unable to verify the session status.",
                    ex);
            }
        }

        return false;
    }

    /// <summary>
    ///     Cleans up expired entries from the PostgreSQL database.
    /// </summary>
    public async Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        if (dbContextFactory != null)
        {
            try
            {
                await using var dbContext = await dbContextFactory.CreateDbContextAsync(cancellationToken);
                var expiredCount = await dbContext.SessionBlacklist
                    .Where(e => e.ExpiresAt <= DateTimeOffset.UtcNow)
                    .ExecuteDeleteAsync(cancellationToken);

                _logger.LogInformation("Successfully deleted {Count} expired sessions from the PostgreSQL database.",
                    expiredCount);
            }
            catch (Exception ex) when (ex is DbException or DbUpdateException or TimeoutException or SocketException
                                           or InvalidOperationException)
            {
                _logger.LogError(ex, "Error during PostgreSQL cleanup.");
            }
        }
    }

    async Task Application.Common.Abstractions.ISessionBlacklistCache.BlacklistSessionAsync(string sessionId,
        TimeSpan ttl, CancellationToken ct)
    {
        var expiresAt = DateTimeOffset.UtcNow.Add(ttl);
        await BlacklistSessionAsync(sessionId, expiresAt, ct);
    }

    async ValueTask<bool> Application.Common.Abstractions.ISessionBlacklistCache.
        IsSessionBlacklistedAsync(string sessionId, CancellationToken ct) => await IsBlacklistedAsync(sessionId, ct);
}
