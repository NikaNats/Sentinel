# Program.cs OpenTelemetry Integration Snippet

Required packages:

```xml
<PackageReference Include="OpenTelemetry.Exporter.OpenTelemetryProtocol" />
<PackageReference Include="OpenTelemetry.Exporter.Prometheus.AspNetCore" />
<PackageReference Include="OpenTelemetry.Extensions.Hosting" />
<PackageReference Include="OpenTelemetry.Instrumentation.AspNetCore" />
```

Add before `var app = builder.Build();`:

```csharp
using System.Diagnostics;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

var otlpEndpoint = builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]
                   ?? "http://otel-collector.observability.svc.cluster.local:4317";

builder.Services.AddOpenTelemetry()
    .ConfigureResource(resource => resource
        .AddService(
            serviceName: builder.Configuration["OTEL_SERVICE_NAME"] ?? "sentinel-api",
            serviceVersion: typeof(Program).Assembly.GetName().Version?.ToString() ?? "1.0.0",
            serviceInstanceId: Environment.MachineName)
        .AddAttributes([
            new KeyValuePair<string, object>("deployment.environment", builder.Environment.EnvironmentName),
            new KeyValuePair<string, object>("service.namespace", "sentinel")
        ]))
    .WithTracing(tracing => tracing
        .AddAspNetCoreInstrumentation(options =>
        {
            options.RecordException = true;
            options.Filter = context =>
                !context.Request.Path.StartsWithSegments("/healthz", StringComparison.Ordinal);
        })
        .AddOtlpExporter(options =>
        {
            options.Endpoint = new Uri(otlpEndpoint, UriKind.Absolute);
            options.Protocol = OtlpExportProtocol.Grpc;
            options.BatchExportProcessorOptions = new BatchExportProcessorOptions<Activity>
            {
                MaxQueueSize = 4096,
                ScheduledDelayMilliseconds = 1000,
                ExporterTimeoutMilliseconds = 3000,
                MaxExportBatchSize = 512
            };
        }))
    .WithMetrics(metrics => metrics
        .AddAspNetCoreInstrumentation()
        .AddMeter("Microsoft.AspNetCore.Hosting")
        .AddMeter("Microsoft.AspNetCore.Server.Kestrel")
        .AddPrometheusExporter()
        .AddOtlpExporter(options =>
        {
            options.Endpoint = new Uri(otlpEndpoint, UriKind.Absolute);
            options.Protocol = OtlpExportProtocol.Grpc;
            options.PeriodicExportingMetricReaderOptions = new PeriodicExportingMetricReaderOptions
            {
                ExportIntervalMilliseconds = 15000,
                ExportTimeoutMilliseconds = 3000
            };
        }));
```

Add after routing/middleware is configured and before `app.Run();`:

```csharp
app.MapPrometheusScrapingEndpoint("/metrics").AllowAnonymous();
```
