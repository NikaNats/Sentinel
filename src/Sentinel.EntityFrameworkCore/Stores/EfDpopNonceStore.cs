namespace Sentinel.EntityFrameworkCore.Stores;

using Sentinel.Security.Abstractions.Nonce;
using Sentinel.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;

/// <summary>
/// Entity Framework Core implementation of IDpopNonceStore.
/// Stores per-client DPoP nonces in a relational database.
/// </summary>
internal sealed class EfDpopNonceStore : IDpopNonceStore
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

    /// <summary>
    /// Atomically verifies if the current nonce matches the expected value, and if so, deletes it.
    /// Executes as a single SQL DELETE WHERE statement to prevent TOCTOU race conditions.
    /// </summary>
    public async Task<bool> ConsumeNonceIfMatchesAsync(string thumbprint, string expectedNonce, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedNonce, nameof(expectedNonce));

        try
        {
            await using var context = _contextFactory.CreateDbContext();

            // Translates to a single, atomic SQL DELETE statement.
            // Returns the number of rows affected. If 1, it matched and was deleted. If 0, it failed.
            var rowsDeleted = await context.DpopNonceStore
                .Where(e => e.Thumbprint == thumbprint
                         && e.Nonce == expectedNonce
                         && e.ExpiresAt > DateTime.UtcNow)
                .ExecuteDeleteAsync(cancellationToken);

            bool wasConsumed = rowsDeleted > 0;

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
            _logger.LogError(ex, "Database unavailable for atomic nonce consumption");
            throw new NonceStoreUnavailableException("Database is unavailable for nonce consumption.", ex);
        }
    }
}
