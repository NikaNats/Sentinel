using Microsoft.AspNetCore.Mvc;

namespace Sentinel.Middleware;

public sealed class ReplayCacheFailureMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        await next(context);

        if (context.Items.TryGetValue("ReplayCacheUnavailable", out var unavailable) && unavailable is true)
        {
            context.Response.Clear();
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await context.Response.WriteAsJsonAsync(new ProblemDetails
            {
                Type = "/errors/replay-cache-unavailable",
                Title = "Security subsystem unavailable",
                Detail = "Token replay protection is temporarily unavailable.",
                Status = StatusCodes.Status503ServiceUnavailable
            });
        }
    }
}
