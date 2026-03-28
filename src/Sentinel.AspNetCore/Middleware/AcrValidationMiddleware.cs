using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

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

                var problem = new ProblemDetails
                {
                    Type = "/errors/invalid_token",
                    Title = "Missing authentication context",
                    Detail = "Authenticated token must include acr claim.",
                    Status = StatusCodes.Status401Unauthorized
                };

                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/problem+json; charset=utf-8";
                await context.Response.WriteAsync(JsonSerializer.Serialize(problem));
                return;
            }
        }

        await next(context);
    }
}
