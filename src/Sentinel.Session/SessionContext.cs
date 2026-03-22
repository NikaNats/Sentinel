namespace Sentinel.Session;

/// <summary>
/// Session context information for request processing.
/// </summary>
public sealed class SessionContext
{
    /// <summary>
    /// Initializes a new instance with session identification and binding information.
    /// </summary>
    /// <param name="sessionId">Session identifier from the authentication token (sid claim).</param>
    /// <param name="dpopThumbprint">Optional DPoP thumbprint for proof-of-possession binding.</param>
    /// <param name="expiresAt">Session expiration time (typically from Keycloak session TTL).</param>
    public SessionContext(string sessionId, string? dpopThumbprint = null, DateTimeOffset? expiresAt = null)
    {
        SessionId = sessionId;
        DpopThumbprint = dpopThumbprint;
        ExpiresAt = expiresAt ?? DateTimeOffset.UtcNow.AddHours(8);
    }

    /// <summary>
    /// Gets the session identifier (typically from Keycloak sid claim).
    /// </summary>
    public string SessionId { get; }

    /// <summary>
    /// Gets the optional DPoP thumbprint bound to this session (for key binding verification).
    /// </summary>
    public string? DpopThumbprint { get; }

    /// <summary>
    /// Gets the session expiration time.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>
    /// Checks if the session has expired.
    /// </summary>
    public bool IsExpired(DateTimeOffset now) => now >= ExpiresAt;
}
