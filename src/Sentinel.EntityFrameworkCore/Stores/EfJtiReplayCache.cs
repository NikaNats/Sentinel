namespace Sentinel.EntityFrameworkCore.Stores;

using Sentinel.Security.Abstractions.Replay;
using Sentinel.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;

/// <summary>
/// Entity Framework Core implementation of IJtiReplayCache.
/// Stores JWT IDs in a relational database to prevent token replay attacks.
/// </summary>
public sealed class EfJtiReplayCache : IJtiReplayCache
{
    private readonly IDbContextFactory<SentinelSecurityDbContext> _contextFactory;
    private readonly ILogger<EfJtiReplayCache> _logger;

    public EfJtiReplayCache(
        IDbContextFactory<SentinelSecurityDbContext> contextFactory,
        ILogger<EfJtiReplayCache> logger)
    {
        _contextFactory = contextFactory ?? throw new ArgumentNullException(nameof(contextFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Marks a JWT ID as used and prevents any further use.
    /// </summary>
    public async Task<bool> TryMarkUsedAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jti, nameof(jti));

        try
        {
            await using var context = _contextFactory.CreateDbContext();

            var entry = new JtiReplayCacheEntry
            {
                Jti = jti,
                ExpiresAt = expiresAt.UtcDateTime
            };

            context.JtiReplayCache.Add(entry);
            await context.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("JTI marked as used in database: {Jti}", jti);
            return true;
        }
        catch (DbUpdateException ex) when (ex.InnerException?.Message.Contains("UNIQUE") ?? false)
        {
            _logger.LogWarning("JTI replay detected: {Jti}", jti);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database unavailable for JTI replay cache");
            throw new ReplayCacheUnavailableException("Database is unavailable for JTI replay cache.", ex);
        }
    }

    /// <summary>
    /// Removes expired JTI entries from the database (garbage collection).
    /// </summary>
    public async Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await using var context = _contextFactory.CreateDbContext();

            var expiredCount = await context.JtiReplayCache
                .Where(e => e.ExpiresAt <= DateTime.UtcNow)
                .ExecuteDeleteAsync(cancellationToken);

            _logger.LogInformation("Cleaned up {Count} expired JTI entries", expiredCount);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database unavailable for JTI cleanup");
            throw new ReplayCacheUnavailableException("Database is unavailable for cleanup.", ex);
        }
    }
}
