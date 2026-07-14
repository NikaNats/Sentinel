namespace Sentinel.Security.Diagnostics;

/// <summary>
///     Emits security events (authentication failures, token replays, session revocation) with structured logging and
///     telemetry.
///     Enforces GDPR/FedRAMP privacy-preserving hashing to prevent persistent identifier leaks in logs and metrics.
/// </summary>
public sealed class SecurityEventEmitter(
    ILogger<SecurityEventEmitter> logger,
    IPrivacyPreservingHasher privacyHasher)
    : ISecurityEventEmitter
{
    /// <summary>
    ///     Structured log message for token replay alerts.
    /// </summary>
    private static readonly Action<ILogger, string, string, string, string, string, Exception?> TokenReplayAlert =
        LoggerMessage.Define<string, string, string, string, string>(
            LogLevel.Critical,
            new EventId(1001, "TokenReplay"),
            "TOKEN_REPLAY_ALERT: Replayed jti {Jti} detected for sub {Sub}, client {ClientId} from IP Hash {IpHash}. CorrelationId={CorrelationId}");

    /// <summary>
    ///     Structured log message for DPoP validation failures.
    /// </summary>
    private static readonly Action<ILogger, string, string, string, string, Exception?> DpopFailureEvent =
        LoggerMessage.Define<string, string, string, string>(
            LogLevel.Warning,
            new EventId(1002, "DpopFailure"),
            "DPOP_FAILURE: Validation failed due to '{Reason}' for thumbprint {Thumbprint} from IP Hash {IpHash}. CorrelationId={CorrelationId}");

    /// <summary>
    ///     Structured log message for session revocation.
    /// </summary>
    private static readonly Action<ILogger, string, string, string, Exception?> SessionRevokedEvent =
        LoggerMessage.Define<string, string, string>(
            LogLevel.Warning,
            new EventId(1003, "SessionRevoked"),
            "SESSION_REVOKED: sessionId {SessionId} for sub {Sub}. CorrelationId={CorrelationId}");

    /// <summary>
    ///     Structured log message for configuration changes.
    /// </summary>
    private static readonly Action<ILogger, string, string, string, string, Exception?> ConfigChangeEvent =
        LoggerMessage.Define<string, string, string, string>(
            LogLevel.Information,
            new EventId(1004, "ConfigChange"),
            "CONFIG_CHANGE: component {Component}, changeType {ChangeType}, details {Details}. CorrelationId={CorrelationId}");

    /// <summary>
    ///     Emits a token replay event with structured logging and metrics.
    /// </summary>
    public void EmitTokenReplay(string jti, string? sub, string? clientId, string ipHash)
    {
        AuthTelemetry.TokenReplays.Add(1);

        TokenReplayAlert(
            logger,
            privacyHasher.Hash(jti),
            string.IsNullOrWhiteSpace(sub) ? "OPAQUE" : privacyHasher.Hash(sub),
            string.IsNullOrWhiteSpace(clientId) ? "UNKNOWN" : privacyHasher.Hash(clientId),
            ipHash,
            GetCorrelationId(),
            null);
    }

    /// <summary>
    ///     Emits a DPoP validation failure event with structured logging and metrics.
    /// </summary>
    public void EmitDpopValidationFailure(string thumbprint, string reason, string ipHash)
    {
        AuthTelemetry.DpopFailures.Add(1);

        DpopFailureEvent(
            logger,
            reason,
            privacyHasher.Hash(thumbprint),
            ipHash,
            GetCorrelationId(),
            null);
    }

    /// <summary>
    ///     Emits a session revocation event.
    /// </summary>
    public void EmitSessionRevoked(string sessionId, string? sub) =>
        SessionRevokedEvent(
            logger,
            privacyHasher.Hash(sessionId),
            string.IsNullOrWhiteSpace(sub) ? "OPAQUE" : privacyHasher.Hash(sub),
            GetCorrelationId(),
            null);

    /// <summary>
    ///     Emits a configuration change event for audit trails.
    /// </summary>
    public void EmitConfigurationChange(string component, string changeType, string details) =>
        ConfigChangeEvent(logger, component, changeType, details, GetCorrelationId(), null);

    /// <summary>
    ///     Gets the correlation ID from the current Activity (W3C Trace Context).
    /// </summary>
    private static string GetCorrelationId()
    {
        var activity = Activity.Current;
        if (activity == null)
        {
            return "NO_TRACE";
        }

        var correlationId = activity.GetBaggageItem("correlation.id");

        return correlationId ?? activity.Id ?? "NO_TRACE";
    }
}
