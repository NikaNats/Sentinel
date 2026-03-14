using System.Diagnostics;
using Sentinel.Application.Common.Abstractions;

namespace Sentinel.Infrastructure.Telemetry;

public sealed class SecurityEventEmitter(ILogger<SecurityEventEmitter> logger) : ISecurityEventEmitter
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

    private static string GetCorrelationId() => Activity.Current?.TraceId.ToString() ?? "NONE";
}
