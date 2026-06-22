using System;
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
///     Hybrid session blacklist cache combining PostgreSQL as persistent source of truth
///     with Redis as a volatile performance accelerator using Write-Through and Read-Through
///     patterns with built-in concurrency protection and fail-closed semantics.
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
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (DbUpdateException ex)
            {
                _logger.LogInformation(ex, "Session {SessionId} already blacklisted by a concurrent request.", sessionId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Critical database persistence failure during session revocation for: {SessionId}", sessionId);
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
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis propagation failed during session revocation for: {SessionId}. DB remains source of truth.", sessionId);
            if (dbContextFactory == null)
            {
                throw new SessionBlacklistUnavailableException("Redis is unavailable and no persistent database is configured.", ex);
            }
        }
    }

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
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Redis cache miss/failure during session check for: {SessionId}. Falling back to DB.", sessionId);
            if (dbContextFactory == null)
            {
                throw new SessionBlacklistUnavailableException("Redis is unavailable and no persistent database is configured.", ex);
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
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        _logger.LogWarning(ex, "Cache back-fill failed for session: {SessionId}", sessionId);
                    }

                    return true;
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Database query failure during blacklist check for: {SessionId}", sessionId);
                throw new SessionBlacklistUnavailableException("The system was unable to verify the session status.", ex);
            }
        }

        return false;
    }

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
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during PostgreSQL session blacklist cleanup. Rethrowing to background service coordinator.");
                throw;
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
