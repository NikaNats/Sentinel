namespace Sentinel.Session;

/// <summary>
/// Manages lifecycle, revocation, and cryptographic binding of sessions.
/// Abstracted interface enables testability and decoupled dependency injection.
/// </summary>
public interface ISessionManager
{
    /// <summary>
    /// Revokes a session by adding it to the blacklist.
    /// Used during logout to prevent token reuse after user signs out.
    /// </summary>
    /// <param name="sessionId">Session identifier to revoke.</param>
    /// <param name="expiresAt">Session lifetime (cache respects TTL for automatic cleanup).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>SecurityResult indicating success or failure (fail-closed on cache unavailable).</returns>
    Task<SecurityResult> RevokeSessionAsync(
        string sessionId,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a session has been revoked (is blacklisted).
    /// </summary>
    /// <param name="sessionId">Session identifier to check.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// SecurityResult&lt;bool&gt;: true if session is blacklisted (revoked), false if active.
    /// Fails closed (returns failure) if cache unavailable.
    /// </returns>
    Task<SecurityResult<bool>> IsSessionRevokedAsync(
        string sessionId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates that a DPoP proof is bound to the correct session's registered key.
    /// Per RFC 9449, the DPoP thumbprint must match the session's binding.
    /// </summary>
    /// <param name="dpopThumbprint">Thumbprint from the DPoP proof.</param>
    /// <param name="sessionDpopThumbprint">Thumbprint registered with the session during authentication.</param>
    /// <returns>true if DPoP proof is bound correctly, false if thumbprints don't match.</returns>
    bool ValidateDpopBinding(string dpopThumbprint, string? sessionDpopThumbprint);
}
