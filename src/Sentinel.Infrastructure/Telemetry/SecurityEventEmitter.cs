using System.Diagnostics;
using Sentinel.Application.Common.Abstractions;

namespace Sentinel.Infrastructure.Telemetry;

public sealed class SecurityEventEmitter(ILogger<SecurityEventEmitter> logger)
    : ISecurityEventEmitter, Sentinel.Security.Abstractions.Security.ISecurityEventEmitter
{
    private static readonly Action<ILogger, string, string, string, string, string, Exception?> TokenReplayAlert =
        LoggerMessage.Define<string, string, string, string, string>(
            LogLevel.Critical,
            new EventId(1001, "TokenReplay"),
            "TOKEN_REPLAY_ALERT: Replayed jti {Jti} detected for sub {Sub}, client {ClientId} from IP Hash {IpHash}. CorrelationId={CorrelationId}");

    private static readonly Action<ILogger, string, string, string, string, Exception?> AuthFailureEvent =
        LoggerMessage.Define<string, string, string, string>(
            LogLevel.Warning,
            new EventId(1002, "AuthFailure"),
            "AUTH_FAILURE: {Reason} for sub {Sub} from IP Hash {IpHash}. CorrelationId={CorrelationId}");

    public void EmitTokenReplay(string jti, string? sub, string? clientId, string ipHash)
    {
        AuthTelemetry.TokenReplays.Add(1, new KeyValuePair<string, object?>("client_id", clientId));
        TokenReplayAlert(logger, jti, sub ?? "OPAQUE", clientId ?? "UNKNOWN", ipHash, GetCorrelationId(), null);
    }

    public void EmitAuthFailure(string reason, string? sub, string ipHash)
    {
        AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("reason", reason));
        AuthFailureEvent(logger, reason, sub ?? "OPAQUE", ipHash, GetCorrelationId(), null);
    }

    // Implementations for Sentinel.Security.Abstractions.Security.ISecurityEventEmitter

    void Sentinel.Security.Abstractions.Security.ISecurityEventEmitter.EmitDpopValidationFailure(string thumbprint, string reason, string ipHash)
    {
        // Map to AuthFailure event with thumbprint context
        AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("thumbprint", thumbprint));
        AuthFailureEvent(logger, $"DPoP validation failure: {reason}", "OPAQUE", ipHash, GetCorrelationId(), null);
    }

    void Sentinel.Security.Abstractions.Security.ISecurityEventEmitter.EmitSessionRevoked(string sessionId, string? sub)
    {
        logger.LogInformation("Session revoked: {SessionId} for sub {Sub}. CorrelationId={CorrelationId}",
            sessionId, sub ?? "OPAQUE", GetCorrelationId());
    }

    void Sentinel.Security.Abstractions.Security.ISecurityEventEmitter.EmitConfigurationChange(string component, string changeType, string details)
    {
        logger.LogWarning("Configuration change in {Component}: {ChangeType}. Details: {Details}. CorrelationId={CorrelationId}",
            component, changeType, details, GetCorrelationId());
    }

    private static string GetCorrelationId() => Activity.Current?.TraceId.ToString() ?? "NONE";
}
