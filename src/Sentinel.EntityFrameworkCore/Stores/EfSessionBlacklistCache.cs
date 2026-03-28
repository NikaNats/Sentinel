using Sentinel.EntityFrameworkCore.Models;
using Sentinel.Security.Abstractions.Session;

namespace Sentinel.EntityFrameworkCore.Stores;

/// <summary>
///     Entity Framework Core implementation of ISessionBlacklistCache.
///     Stores revoked/logged out sessions in a relational database.
/// </summary>
internal sealed class EfSessionBlacklistCache : ISessionBlacklistCache
{
    private readonly IDbContextFactory<SentinelSecurityDbContext> _contextFactory;
    private readonly ILogger<EfSessionBlacklistCache> _logger;

    public EfSessionBlacklistCache(
        IDbContextFactory<SentinelSecurityDbContext> contextFactory,
        ILogger<EfSessionBlacklistCache> logger)
    {
        _contextFactory = contextFactory ?? throw new ArgumentNullException(nameof(contextFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    ///     Blacklists a session (marks it as revoked/logged out).
    /// </summary>
    public async Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        try
        {
            await using var context = _contextFactory.CreateDbContext();

            var entry = new SessionBlacklistEntry
            {
                SessionId = sessionId,
                ExpiresAt = expiresAt
            };

            context.SessionBlacklist.Add(entry);
            await context.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Session blacklisted in database: {SessionId}", sessionId);
        }
        catch (DbUpdateException)
        {
            // Provider-agnostic UNIQUE constraint violation detection.
            // The SessionId column has a unique constraint; if we reach here, it's already blacklisted.
            _logger.LogInformation("Session already blacklisted: {SessionId}", sessionId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database unavailable for session blacklist");
            throw new SessionBlacklistUnavailableException("Database is unavailable for session blacklist.", ex);
        }
    }

    /// <summary>
    ///     Checks if a session is blacklisted (revoked).
    /// </summary>
    public async Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        try
        {
            await using var context = _contextFactory.CreateDbContext();

            var isBlacklisted = await context.SessionBlacklist
                .Where(e => e.SessionId == sessionId && e.ExpiresAt > DateTimeOffset.UtcNow)
                .AnyAsync(cancellationToken);

            _logger.LogInformation("Session blacklist check for: {SessionId}, blacklisted: {IsBlacklisted}", sessionId,
                isBlacklisted);
            return isBlacklisted;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database unavailable for session blacklist check");
            throw new SessionBlacklistUnavailableException("Database is unavailable for session blacklist check.", ex);
        }
    }

    /// <summary>
    ///     Removes expired entries from the database (garbage collection).
    /// </summary>
    public async Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await using var context = _contextFactory.CreateDbContext();

            var expiredCount = await context.SessionBlacklist
                .Where(e => e.ExpiresAt <= DateTimeOffset.UtcNow)
                .ExecuteDeleteAsync(cancellationToken);

            _logger.LogInformation("Cleaned up {Count} expired session entries", expiredCount);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database unavailable for session cleanup");
            throw new SessionBlacklistUnavailableException("Database is unavailable for cleanup.", ex);
        }
    }
}
