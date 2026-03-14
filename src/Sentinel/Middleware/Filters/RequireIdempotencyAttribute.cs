using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.Caching.Distributed;

namespace Sentinel.Middleware.Filters;

[AttributeUsage(AttributeTargets.Method)]
public sealed class RequireIdempotencyAttribute : Attribute, IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        const string headerName = "Idempotency-Key";

        if (!context.HttpContext.Request.Headers.TryGetValue(headerName, out var keyValues)
            || string.IsNullOrWhiteSpace(keyValues.ToString()))
        {
            context.Result = new BadRequestObjectResult(new ProblemDetails
            {
                Type = "/errors/missing-idempotency-key",
                Title = "Idempotency Key Required",
                Detail = $"The '{headerName}' header is required for this operation.",
                Status = StatusCodes.Status400BadRequest
            });
            return;
        }

        var idempotencyKey = keyValues.ToString();
        var cache = context.HttpContext.RequestServices.GetRequiredService<IDistributedCache>();
        var sub = context.HttpContext.User.FindFirst("sub")?.Value ?? "anonymous";
        var redisKey = $"idempotency:{sub}:{idempotencyKey}";

        var exists = await cache.GetStringAsync(redisKey, context.HttpContext.RequestAborted);
        if (exists is not null)
        {
            context.Result = new ConflictObjectResult(new ProblemDetails
            {
                Type = "/errors/idempotency-conflict",
                Title = "Request Already Processed",
                Detail = "A request with this Idempotency-Key has already been successfully processed.",
                Status = StatusCodes.Status409Conflict
            });
            return;
        }

        var executedContext = await next();

        if (executedContext.Exception is null && IsSuccessfulResult(executedContext.Result))
        {
            var options = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(24)
            };

            await cache.SetStringAsync(redisKey, "processed", options, context.HttpContext.RequestAborted);
        }
    }

    private static bool IsSuccessfulResult(IActionResult? result)
    {
        if (result is IStatusCodeActionResult statusCodeResult)
        {
            var statusCode = statusCodeResult.StatusCode ?? StatusCodes.Status200OK;
            return statusCode is >= 200 and < 300;
        }

        return result is not null;
    }
}
