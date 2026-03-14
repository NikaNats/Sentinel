using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Sentinel.Infrastructure.Telemetry;

public static class AuthTelemetry
{
    public const string SourceName = "Sentinel.Auth.Tracing";
    public const string MeterName = "Sentinel.Auth.Metrics";

    public static readonly ActivitySource Source = new(SourceName);
    public static readonly Meter Meter = new(MeterName);

    public static readonly Counter<long> DpopFailures = Meter.CreateCounter<long>(
        "auth.dpop.failures",
        description: "Number of DPoP validation failures");

    public static readonly Counter<long> TokenReplays = Meter.CreateCounter<long>(
        "auth.jti.replays_total",
        description: "Number of token replay attempts detected");

    public static readonly Counter<long> TokenIssued = Meter.CreateCounter<long>(
        "auth.token.issued",
        description: "Number of issued tokens by assurance level");

    public static readonly Histogram<double> ValidationDuration = Meter.CreateHistogram<double>(
        "auth.token.validation.duration_ms",
        unit: "ms");
}
