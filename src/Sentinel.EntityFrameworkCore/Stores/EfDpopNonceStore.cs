namespace Sentinel.EntityFrameworkCore.Stores;

using Sentinel.Security.Abstractions.Nonce;
using Sentinel.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;

/// <summary>
/// Entity Framework Core implementation of IDpopNonceStore.
/// Stores per-client DPoP nonces in a relational database.
/// </summary>
public sealed class EfDpopNonceStore : IDpopNonceStore
{
    private readonly IDbContextFactory<SentinelSecurityDbContext> _contextFactory;
    private readonly ILogger<EfDpopNonceStore> _logger;

    public EfDpopNonceStore(
        IDbContextFactory<SentinelSecurityDbContext> contextFactory,
        ILogger<EfDpopNonceStore> logger)
    {
        _contextFactory = contextFactory ?? throw new ArgumentNullException(nameof(contextFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Retrieves the current nonce for a given client (identified by JWK thumbprint).
    /// </summary>
    public async Task<string?> GetNonceAsync(string thumbprint, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));

        try
        {
            await using var context = _contextFactory.CreateDbContext();

            var entry = await context.DpopNonceStore
                .Where(e => e.Thumbprint == thumbprint && e.ExpiresAt > DateTime.UtcNow)
                .FirstOrDefaultAsync(cancellationToken);

            if (entry == null)
            {
                _logger.LogInformation("No valid nonce found for thumbprint: {Thumbprint}", thumbprint);
                return null;
            }

            _logger.LogInformation("Nonce retrieved for thumbprint: {Thumbprint}", thumbprint);
            return entry.Nonce;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database unavailable for nonce retrieval");
            throw new NonceStoreUnavailableException("Database is unavailable for nonce retrieval.", ex);
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
            await using var context = _contextFactory.CreateDbContext();

            // Remove old nonce for this thumbprint
            await context.DpopNonceStore
                .Where(e => e.Thumbprint == thumbprint)
                .ExecuteDeleteAsync(cancellationToken);

            // Add new nonce
            var entry = new DpopNonceEntry
            {
                Thumbprint = thumbprint,
                Nonce = nonce,
                ExpiresAt = expiresAt.UtcDateTime
            };

            context.DpopNonceStore.Add(entry);
            await context.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Nonce set for thumbprint: {Thumbprint}", thumbprint);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database unavailable for nonce storage");
            throw new NonceStoreUnavailableException("Database is unavailable for nonce storage.", ex);
        }
    }

    /// <summary>
    /// Removes expired nonce entries from the database (garbage collection).
    /// </summary>
    public async Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await using var context = _contextFactory.CreateDbContext();

            var expiredCount = await context.DpopNonceStore
                .Where(e => e.ExpiresAt <= DateTime.UtcNow)
                .ExecuteDeleteAsync(cancellationToken);

            _logger.LogInformation("Cleaned up {Count} expired nonce entries", expiredCount);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database unavailable for nonce cleanup");
            throw new NonceStoreUnavailableException("Database is unavailable for cleanup.", ex);
        }
    }
}
