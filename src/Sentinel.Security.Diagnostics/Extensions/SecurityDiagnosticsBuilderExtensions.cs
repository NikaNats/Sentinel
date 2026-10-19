using Microsoft.Extensions.DependencyInjection;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Sentinel.Security.Abstractions.DependencyInjection;

namespace Sentinel.Security.Diagnostics.Extensions;

/// <summary>
///     Adds OpenTelemetry tracing and metrics wiring for Sentinel security diagnostics.
/// </summary>
public static class SecurityDiagnosticsBuilderExtensions
{
    /// <summary>
    ///     Registers the Sentinel activity source and meter with OpenTelemetry. Exporters are host-owned:
    ///     add <c>AddOtlpExporter()</c>, a Prometheus exporter or any other exporter in the host.
    /// </summary>
    public static ISentinelSecurityBuilder AddSecurityTelemetry(this ISentinelSecurityBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        _ = builder.Services.AddOpenTelemetry()
            .WithTracing(t => t
                .AddAspNetCoreInstrumentation()
                .AddSource(AuthTelemetry.SourceName))
            .WithMetrics(m => m
                .AddAspNetCoreInstrumentation()
                .AddMeter(AuthTelemetry.MeterName));

        return builder;
    }
}
