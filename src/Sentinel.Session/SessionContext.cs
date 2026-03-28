namespace Sentinel.Session;

/// <summary>
///     Session context information for request processing.
///     Immutable record enforcing null-safety and lifetime bounds.
/// </summary>
public sealed record SessionContext
{
    /// <summary>
    ///     Initializes a new instance with session identification and binding information.
    /// </summary>
    /// <param name="sessionId">Session identifier from the authentication token (sid claim).</param>
    /// <param name="expiresAt">Session expiration time.</param>
    /// <param name="dpopThumbprint">Optional DPoP thumbprint for proof-of-possession binding.</param>
    public SessionContext(string sessionId, DateTimeOffset expiresAt, string? dpopThumbprint = null)
    {
        // ✅ GUARD: Enforce non-null, non-empty session identifiers
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        SessionId = sessionId;
        ExpiresAt = expiresAt;
        DpopThumbprint = dpopThumbprint;
    }

    /// <summary>
    ///     Gets the session identifier (typically from Keycloak sid claim).
    /// </summary>
    public string SessionId { get; }

    /// <summary>
    ///     Gets the optional DPoP thumbprint bound to this session.
    /// </summary>
    public string? DpopThumbprint { get; }

    /// <summary>
    ///     Gets the session expiration time.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>
    ///     Checks if the session has expired against the provided time.
    /// </summary>
    public bool IsExpired(DateTimeOffset now) => now >= ExpiresAt;
}
