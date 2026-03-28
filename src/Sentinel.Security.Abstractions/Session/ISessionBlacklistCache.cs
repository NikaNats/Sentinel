namespace Sentinel.Security.Abstractions.Session;

/// <summary>
///     Redis-backed (or equivalent) session blacklist for logout and revocation flows.
/// </summary>
public interface ISessionBlacklistCache
{
    /// <summary>
    ///     Blacklists a session (marks it as revoked/logged out).
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="expiresAt">UTC time when this entry should be automatically removed.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="Exceptions.SessionBlacklistUnavailableException">Thrown if the cache is unreachable.</exception>
    Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);

    /// <summary>
    ///     Checks if a session is blacklisted (revoked).
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the session is blacklisted, false otherwise.</returns>
    /// <exception cref="Exceptions.SessionBlacklistUnavailableException">Thrown if the cache is unreachable.</exception>
    Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    ///     Removes expired entries (garbage collection).
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="Exceptions.SessionBlacklistUnavailableException">Thrown if the cache is unreachable.</exception>
    Task CleanupExpiredAsync(CancellationToken cancellationToken = default);
}
