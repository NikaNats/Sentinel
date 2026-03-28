namespace Sentinel.Security.Diagnostics;

/// <summary>
/// Centralized telemetry metrics and activities for Sentinel authentication and authorization events.
/// Native to the Security layer - can be used independently of any application infrastructure.
///
/// IMPORTANT LIFECYCLE NOTE:
/// Because Meter and ActivitySource are static, they must be registered with the OpenTelemetry SDK
/// during host startup (e.g., using AddMeter and AddSource in the OpenTelemetry configuration).
/// The OTel SDK's IHostedService will ensure they are properly flushed and disposed during an
/// application shutdown (SIGTERM), preventing the loss of critical security events in the final seconds
/// of operation (which may contain traces of exploits that caused the crash).
/// </summary>
public static class AuthTelemetry
{
    /// <summary>
    /// Activity source name for distributed tracing (OpenTelemetry).
    /// </summary>
    public const string SourceName = "Sentinel.Auth.Tracing";

    /// <summary>
    /// Meter name for metrics collection (OpenTelemetry).
    /// </summary>
    public const string MeterName = "Sentinel.Auth.Metrics";

    /// <summary>
    /// Activity source for creating spans (W3C Trace Context compatible).
    /// </summary>
    public static readonly ActivitySource Source = new(SourceName);

    /// <summary>
    /// Meter for recording authentication metrics (OpenTelemetry Metrics).
    /// </summary>
    public static readonly Meter Meter = new(MeterName);

    /// <summary>
    /// Counter: DPoP proof validation failures.
    /// </summary>
    public static readonly Counter<long> DpopFailures = Meter.CreateCounter<long>(
        "auth.dpop.failures",
        description: "Number of DPoP validation failures");

    /// <summary>
    /// Counter: Token replay attempts (JTI duplicates).
    /// </summary>
    public static readonly Counter<long> TokenReplays = Meter.CreateCounter<long>(
        "auth.jti.replays_total",
        description: "Number of token replay attempts detected");

    /// <summary>
    /// Counter: Successfully issued tokens.
    /// </summary>
    public static readonly Counter<long> TokenIssued = Meter.CreateCounter<long>(
        "auth.token.issued",
        description: "Number of issued tokens by assurance level");

    /// <summary>
    /// Histogram: Token validation latency in seconds.
    /// ✅ FIX: Renamed to remove _ms suffix; unit set to "s" strictly following OTel Semantic Conventions.
    /// Prometheus/OTLP require metrics to use seconds for duration measurements, not milliseconds.
    /// </summary>
    public static readonly Histogram<double> ValidationDuration = Meter.CreateHistogram<double>(
        "auth.token.validation.duration",
        unit: "s",
        description: "Duration of token validation in seconds");

    /// <summary>
    /// Counter: Redis degradation events triggering node-local replay protection.
    /// </summary>
    public static readonly Counter<long> RedisDegradedModeActivations = Meter.CreateCounter<long>(
        "auth.redis.degraded_mode_activations",
        description: "Number of transitions into node-local replay protection mode.");
}
