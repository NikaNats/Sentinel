namespace Sentinel.Session;

/// <summary>
/// Session manager for handling logout, revocation, and binding validation.
/// Coordinates session blacklist and optional DPoP proof-of-possession binding.
/// </summary>
public sealed class SessionManager
{
    private readonly ISessionBlacklistCache _blacklist;

    /// <summary>
    /// Initializes a new instance with a session blacklist cache.
    /// </summary>
    /// <param name="blacklist">Cache for tracking revoked/blacklisted sessions.</param>
    public SessionManager(ISessionBlacklistCache blacklist)
    {
        _blacklist = blacklist;
    }

    /// <summary>
    /// Attempts to revoke a session by adding it to the blacklist.
    /// Used for logout endpoint to prevent token reuse after user signs out.
    /// </summary>
    /// <param name="sessionId">Session identifier to revoke.</param>
    /// <param name="expiresAt">Session lifetime (cache should remove entry automatically).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// Success result on successful blacklist, failure if cache unavailable.
    /// </returns>
    public async Task<SecurityResult> RevokeSessionAsync(
        string sessionId,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await _blacklist.BlacklistSessionAsync(sessionId, expiresAt, cancellationToken);
            return SecurityResult.CreateSuccess();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Fail closed: if blacklist is unavailable, don't allow login without revocation guarantee
            return SecurityResult.Failure($"revocation_unavailable: {ex.Message}");
        }
    }

    /// <summary>
    /// Checks if a session has been revoked (is blacklisted).
    /// </summary>
    /// <param name="sessionId">Session identifier to check.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// True if session is blacklisted (revoked), false if active.
    /// Throws if cache unavailable (fail closed).
    /// </returns>
    public async Task<bool> IsSessionRevokedAsync(
        string sessionId,
        CancellationToken cancellationToken = default)
    {
        return await _blacklist.IsBlacklistedAsync(sessionId, cancellationToken);
    }

    /// <summary>
    /// Validates that a DPoP proof is bound to the correct session's registered key.
    /// Per RFC 9449, the DPoP thumbprint must match the session's binding.
    /// </summary>
    /// <param name="sessionId">Session identifier claimed in the token.</param>
    /// <param name="dpopThumbprint">Thumbprint from the DPoP proof.</param>
    /// <param name="sessionDpopThumbprint">Thumbprint registered with the session during authentication.</param>
    /// <returns>
    /// True if DPoP proof is bound correctly, false if thumbprints don't match.
    /// </returns>
    public static bool ValidateDpopBinding(
        string sessionId,
        string dpopThumbprint,
        string? sessionDpopThumbprint)
    {
        // Session may not have DPoP binding (e.g., non-browser clients)
        if (string.IsNullOrEmpty(sessionDpopThumbprint))
        {
            return true;
        }

        // If session requires DPoP binding, proof thumbprint must match
        return string.Equals(dpopThumbprint, sessionDpopThumbprint, StringComparison.Ordinal);
    }
}
