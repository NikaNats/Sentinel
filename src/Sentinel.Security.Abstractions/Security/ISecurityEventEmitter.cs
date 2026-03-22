namespace Sentinel.Security.Abstractions.Security;

/// <summary>
/// Emits structured SIEM/audit events for security-relevant occurrences.
/// Implementations must not throw — failures to emit must be logged and swallowed.
/// </summary>
public interface ISecurityEventEmitter
{
    /// <summary>
    /// Emits an event when a JWT token replay is detected.
    /// </summary>
    /// <param name="jti">The JWT ID claim.</param>
    /// <param name="sub">Subject claim (optional).</param>
    /// <param name="clientId">OAuth 2.0 client ID (optional).</param>
    /// <param name="ipHash">One-way hash of the client IP address.</param>
    void EmitTokenReplay(string jti, string? sub, string? clientId, string ipHash);

    /// <summary>
    /// Emits an event when a DPoP proof validation fails.
    /// </summary>
    void EmitDpopValidationFailure(string thumbprint, string reason, string ipHash);

    /// <summary>
    /// Emits an event when a session is revoked or blacklisted.
    /// </summary>
    void EmitSessionRevoked(string sessionId, string? sub);

    /// <summary>
    /// Emits an event when a security-relevant configuration change occurs.
    /// </summary>
    void EmitConfigurationChange(string component, string changeType, string details);
}
