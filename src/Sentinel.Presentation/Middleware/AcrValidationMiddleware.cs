using Microsoft.AspNetCore.Mvc;

namespace Sentinel.Middleware;

public sealed class AcrValidationMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.User?.Identity?.IsAuthenticated == true)
        {
            var acr = context.User.FindFirst("acr")?.Value;
            if (string.IsNullOrWhiteSpace(acr))
            {
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
