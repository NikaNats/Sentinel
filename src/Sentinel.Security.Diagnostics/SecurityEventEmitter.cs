namespace Sentinel.Security.Diagnostics;

/// <summary>
/// Emits security events (authentication failures, token replays, session revocation) with structured logging and telemetry.
/// Enables security-aware tracing across the entire distributed system.
/// </summary>
public sealed class SecurityEventEmitter(ILogger<SecurityEventEmitter> logger)
    : ISecurityEventEmitter
{
    /// <summary>
    /// Structured log message for token replay alerts.
    /// </summary>
    private static readonly Action<ILogger, string, string, string, string, string, Exception?> TokenReplayAlert =
        LoggerMessage.Define<string, string, string, string, string>(
            LogLevel.Critical,
            new EventId(1001, "TokenReplay"),
            "TOKEN_REPLAY_ALERT: Replayed jti {Jti} detected for sub {Sub}, client {ClientId} from IP Hash {IpHash}. CorrelationId={CorrelationId}");

    /// <summary>
    /// Structured log message for authentication failures.
    /// </summary>
    private static readonly Action<ILogger, string, string, string, string, Exception?> AuthFailureEvent =
        LoggerMessage.Define<string, string, string, string>(
            LogLevel.Warning,
            new EventId(1002, "AuthFailure"),
            "AUTH_FAILURE: {Reason} for sub {Sub} from IP Hash {IpHash}. CorrelationId={CorrelationId}");

    /// <summary>
    /// Structured log message for session revocation.
    /// </summary>
    private static readonly Action<ILogger, string, string, string, Exception?> SessionRevokedEvent =
        LoggerMessage.Define<string, string, string>(
            LogLevel.Warning,
            new EventId(1003, "SessionRevoked"),
            "SESSION_REVOKED: sessionId {SessionId} for sub {Sub}. CorrelationId={CorrelationId}");

    /// <summary>
    /// Structured log message for configuration changes.
    /// </summary>
    private static readonly Action<ILogger, string, string, string, string, Exception?> ConfigChangeEvent =
        LoggerMessage.Define<string, string, string, string>(
            LogLevel.Information,
            new EventId(1004, "ConfigChange"),
            "CONFIG_CHANGE: component {Component}, changeType {ChangeType}, details {Details}. CorrelationId={CorrelationId}");

    /// <summary>
    /// Emits a token replay event with structured logging and metrics.
    /// </summary>
    public void EmitTokenReplay(string jti, string? sub, string? clientId, string ipHash)
    {
        AuthTelemetry.TokenReplays.Add(1, new KeyValuePair<string, object?>("client_id", clientId));
        TokenReplayAlert(logger, jti, sub ?? "OPAQUE", clientId ?? "UNKNOWN", ipHash, GetCorrelationId(), null);
    }

    /// <summary>
    /// Emits a DPoP validation failure event with structured logging and metrics.
    /// </summary>
    public void EmitDpopValidationFailure(string thumbprint, string reason, string ipHash)
    {
        AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("thumbprint", thumbprint));
        AuthFailureEvent(logger, $"DPoP validation failure: {reason}", "OPAQUE", ipHash, GetCorrelationId(), null);
    }

    /// <summary>
    /// Emits a session revocation event.
    /// </summary>
    public void EmitSessionRevoked(string sessionId, string? sub)
    {
        SessionRevokedEvent(logger, sessionId, sub ?? "OPAQUE", GetCorrelationId(), null);
    }

    /// <summary>
    /// Emits a configuration change event for audit trails.
    /// </summary>
    public void EmitConfigurationChange(string component, string changeType, string details)
    {
        ConfigChangeEvent(logger, component, changeType, details, GetCorrelationId(), null);
    }

    /// <summary>
    /// Gets the correlation ID from the current Activity (W3C Trace Context).
    /// Falls back to Activity ID if no baggage is set.
    /// </summary>
    private static string GetCorrelationId()
    {
        var activity = Activity.Current;
        if (activity == null)
            return "NO_TRACE";

        // Check baggage for explicit correlation ID
        if (activity.Baggage.Any())
        {
            var correlationBaggage = activity.Baggage.FirstOrDefault(b => b.Key == "correlation.id");
            if (correlationBaggage.Key != null)
                return correlationBaggage.Value ?? activity.Id ?? "NO_TRACE";
        }

        return activity.Id ?? "NO_TRACE";
    }
}
