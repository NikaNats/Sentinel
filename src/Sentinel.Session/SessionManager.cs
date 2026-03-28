namespace Sentinel.Session;

/// <summary>
/// Session manager for handling logout, revocation, and binding validation.
/// Coordinates session blacklist and optional DPoP proof-of-possession binding.
/// </summary>
public sealed class SessionManager : ISessionManager
{
    private readonly ISessionBlacklistCache _blacklist;
    private readonly SessionManagementOptions _options;
    private readonly ILogger<SessionManager> _logger;

    /// <summary>
    /// Initializes a new instance with session blacklist cache, configuration, and logging.
    /// </summary>
    /// <param name="blacklist">Cache for tracking revoked/blacklisted sessions.</param>
    /// <param name="options">Configuration for session management behavior.</param>
    /// <param name="logger">Logger for diagnostic and error information.</param>
    public SessionManager(
        ISessionBlacklistCache blacklist,
        IOptions<SessionManagementOptions> options,
        ILogger<SessionManager> logger)
    {
        // ✅ GUARD: Enforce non-null dependencies
        ArgumentNullException.ThrowIfNull(blacklist);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _blacklist = blacklist;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>
    /// Attempts to revoke a session by adding it to the blacklist.
    /// Used for logout endpoint to prevent token reuse after user signs out.
    /// </summary>
    /// <param name="sessionId">Session identifier to revoke.</param>
    /// <param name="expiresAt">Session lifetime (cache should remove entry automatically).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// Success result on successful blacklist, fail-closed result if cache unavailable.
    /// </returns>
    public async Task<SecurityResult> RevokeSessionAsync(
        string sessionId,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        // ✅ GUARD: Enforce non-empty session identifiers
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        try
        {
            await _blacklist.BlacklistSessionAsync(sessionId, expiresAt, cancellationToken);
            _logger.LogInformation("Session {SessionId} successfully revoked and blacklisted.", sessionId);

            return SecurityResult.CreateSuccess();
        }
        catch (OperationCanceledException)
        {
            // Don't log cancellations as errors - they're expected in some scenarios
            throw;
        }
#pragma warning disable CA1031 // Do not catch general exception types
        catch (Exception ex)
        {
            // ✅ Intentional broad exception catch: fail-closed security pattern
            // We catch all exceptions to guarantee revocation_unavailable result.
            // Any cache communication failure (Redis, network, permission, etc.) must fail safely.

            // ✅ SANITIZE: Log the sensitive topological details internally
            _logger.LogError(
                ex,
                "Failed to interact with the blacklist cache while revoking session {SessionId}.",
                sessionId);

            // ✅ FAIL CLOSED: Return sanitized result without leaking exception details
            return SecurityResult.Failure("revocation_unavailable");
        }
#pragma warning restore CA1031
    }

    /// <summary>
    /// Checks if a session has been revoked (is blacklisted).
    /// </summary>
    /// <param name="sessionId">Session identifier to check.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// SecurityResult&lt;bool&gt; with true if revoked, false if active.
    /// Fails closed (returns failure) if cache unavailable.
    /// </returns>
    public async Task<SecurityResult<bool>> IsSessionRevokedAsync(
        string sessionId,
        CancellationToken cancellationToken = default)
    {
        // ✅ GUARD: Enforce non-empty session identifiers
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        try
        {
            var isRevoked = await _blacklist.IsBlacklistedAsync(sessionId, cancellationToken);
            return SecurityResultFactory.Create(isRevoked);
        }
        catch (OperationCanceledException)
        {
            // Don't catch cancellations - propagate them
            throw;
        }
#pragma warning disable CA1031 // Do not catch general exception types
        catch (Exception ex)
        {
            // ✅ Intentional broad exception catch: fail-closed security pattern
            // We catch all exceptions to guarantee revocation_check_unavailable result.
            // Any cache communication failure (Redis, network, permission, etc.) must fail safely.

            // ✅ SANITIZE: Log the sensitive topological details internally
            _logger.LogError(
                ex,
                "Failed to query the blacklist cache for session {SessionId}. Failing closed.",
                sessionId);

            // ✅ FAIL CLOSED: If we cannot verify the session state, assume it is unsafe
            return SecurityResultFactory.Failure<bool>("revocation_check_unavailable");
        }
#pragma warning restore CA1031
    }

    /// <summary>
    /// Validates that a DPoP proof is bound to the correct session's registered key.
    /// Per RFC 9449, the DPoP thumbprint must match the session's binding.
    /// </summary>
    /// <param name="dpopThumbprint">Thumbprint from the DPoP proof.</param>
    /// <param name="sessionDpopThumbprint">Thumbprint registered with the session during authentication.</param>
    /// <returns>
    /// true if DPoP proof is bound correctly, false if thumbprints don't match or binding required but missing.
    /// </returns>
    public bool ValidateDpopBinding(string dpopThumbprint, string? sessionDpopThumbprint)
    {
        // ✅ GUARD: Enforce non-empty DPoP thumbprints
        ArgumentException.ThrowIfNullOrWhiteSpace(dpopThumbprint);

        // Session may not have DPoP binding (e.g., non-browser clients, public clients)
        if (string.IsNullOrEmpty(sessionDpopThumbprint))
        {
            // ✅ COHESIVE: Configuration dictates whether binding is required
            if (_options.RequireDpopBinding)
            {
                _logger.LogWarning(
                    "DPoP validation failed: Session requires DPoP binding (configured RequireDpopBinding={RequireDpopBinding}), but no thumbprint was registered.",
                    _options.RequireDpopBinding);
                return false;
            }

            return true;
        }

        // ✅ SYMMETRIC: If session HAS binding, it must match the proof
        var isValid = string.Equals(dpopThumbprint, sessionDpopThumbprint, StringComparison.Ordinal);

        if (!isValid)
        {
            _logger.LogWarning(
                "DPoP validation failed: Provided thumbprint does not match session thumbprint.");
        }

        return isValid;
    }
}
