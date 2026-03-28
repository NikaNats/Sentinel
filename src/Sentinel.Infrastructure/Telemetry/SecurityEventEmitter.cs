using System.Diagnostics;
using Sentinel.Security.Abstractions.Security;

namespace Sentinel.Infrastructure.Telemetry;

public sealed class SecurityEventEmitter(ILogger<SecurityEventEmitter> logger)
    : ISecurityEventEmitter
{
    private static readonly Action<ILogger, string, string, string, string, string, Exception?> TokenReplayAlert =
        LoggerMessage.Define<string, string, string, string, string>(
            LogLevel.Critical,
            new EventId(1001, "TokenReplay"),
            "TOKEN_REPLAY_ALERT: Replayed jti {Jti} detected for sub {Sub}, client {ClientId} from IP Hash {IpHash}. CorrelationId={CorrelationId}");

    private static readonly Action<ILogger, string, string, string, string, Exception?> DpopFailureAlert =
        LoggerMessage.Define<string, string, string, string>(
            LogLevel.Warning,
            new EventId(1002, "DpopFailure"),
            "DPOP_FAILURE: {Reason} for reason {Thumbprint} from IP Hash {IpHash}. CorrelationId={CorrelationId}");

    public void EmitTokenReplay(string jti, string? sub, string? clientId, string ipHash)
    {
        AuthTelemetry.TokenReplays.Add(1, new KeyValuePair<string, object?>("client_id", clientId));
        TokenReplayAlert(logger, jti, sub ?? "OPAQUE", clientId ?? "UNKNOWN", ipHash, GetCorrelationId(), null);
    }

    public void EmitDpopValidationFailure(string thumbprint, string reason, string ipHash)
    {
        // Map to DPoP failure event with thumbprint context
        AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("thumbprint", thumbprint));
        DpopFailureAlert(logger, reason, thumbprint, ipHash, GetCorrelationId(), null);
    }

    public void EmitSessionRevoked(string sessionId, string? sub)
    {
        logger.LogInformation("Session revoked: {SessionId} for sub {Sub}. CorrelationId={CorrelationId}",
            sessionId, sub ?? "OPAQUE", GetCorrelationId());
    }

    public void EmitConfigurationChange(string component, string changeType, string details)
    {
        logger.LogWarning(
            "Configuration change in {Component}: {ChangeType}. Details: {Details}. CorrelationId={CorrelationId}",
            component, changeType, details, GetCorrelationId());
    }

    private static string GetCorrelationId() => Activity.Current?.TraceId.ToString() ?? "NONE";
}
