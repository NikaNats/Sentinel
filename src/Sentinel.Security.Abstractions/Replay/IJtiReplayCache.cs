namespace Sentinel.Security.Abstractions.Replay;

/// <summary>
///     Stores JWT IDs (jti claims) to prevent token replay attacks.
///     Implementations MUST be fail-closed: if storage is unavailable,
///     throw <see cref="Exceptions.ReplayCacheUnavailableException" /> —
///     never return true (allow) when storage cannot be verified.
/// </summary>
public interface IJtiReplayCache
{
    /// <summary>
    ///     Marks a JWT ID as used and prevents any further use of the same token.
    /// </summary>
    /// <param name="jti">The JWT ID claim value.</param>
    /// <param name="expiresAt">The UTC time when this JTI should be removed from the cache (typically token expiry).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    ///     True if the record was successfully stored (JTI had not been seen before). False if the JTI was already in
    ///     cache (replay).
    /// </returns>
    /// <exception cref="Exceptions.ReplayCacheUnavailableException">Thrown if the cache backend is unreachable.</exception>
    Task<bool> TryMarkUsedAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);

    /// <summary>
    ///     Removes expired JTI entries from the cache (garbage collection).
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="Exceptions.ReplayCacheUnavailableException">Thrown if the cache backend is unreachable.</exception>
    Task CleanupExpiredAsync(CancellationToken cancellationToken = default);
}
