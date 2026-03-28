using System.Diagnostics;

namespace Sentinel.AspNetCore.Middleware;

/// <summary>
///     Propagates correlation ID and DPoP/security context via Activity baggage.
///     Enables downstream services (SQL auditing, messaging, etc.) to correlate security events.
/// </summary>
public sealed class CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
{
    private const string HeaderName = "X-Correlation-ID";

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = context.Request.Headers[HeaderName].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(correlationId))
        {
            correlationId = Activity.Current?.TraceId.ToString() ?? Guid.NewGuid().ToString("N");
        }

        context.Items[HeaderName] = correlationId;
        context.Response.Headers[HeaderName] = correlationId;

        // Propagate via Activity baggage for downstream services (SQL auditing, messaging, etc.)
        Activity.Current?.AddBaggage("correlationId", correlationId);

        // If DPoP key is bound, propagate it for security audit trails
        if (context.Items.TryGetValue("dpop.jkt", out var dPoPJkt))
        {
            Activity.Current?.AddBaggage("dpop.jkt", dPoPJkt?.ToString() ?? string.Empty);
        }

        using (logger.BeginScope(new Dictionary<string, object>
               {
                   ["CorrelationId"] = correlationId,
                   ["DPoPKey"] = dPoPJkt?.ToString() ?? "none"
               }))
        {
            await next(context);
        }
    }
}
