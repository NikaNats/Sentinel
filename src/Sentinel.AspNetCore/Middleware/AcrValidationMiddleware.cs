using Microsoft.AspNetCore.Mvc;

namespace Sentinel.AspNetCore.Middleware;

public sealed class AcrValidationMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.User?.Identity?.IsAuthenticated == true)
        {
            var acr = context.User.FindFirst("acr")?.Value;
            if (string.IsNullOrWhiteSpace(acr))
            {
                // ✅ FIX: Guard against modifying an already-started response
                // This prevents InvalidOperationException crashes when response stream is already in use
                if (context.Response.HasStarted)
                {
                    // Cannot write headers/body. Log and abort to prevent pipeline crash.
                    return;
                }

                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new ProblemDetails
                {
                    Type = "/errors/invalid_token",
                    Title = "Missing authentication context",
                    Detail = "Authenticated token must include acr claim.",
                    Status = StatusCodes.Status401Unauthorized
                });
                return;
            }
        }

        await next(context);
    }
}
