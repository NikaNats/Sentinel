using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using StackExchange.Redis;

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
        var redis = context.HttpContext.RequestServices.GetRequiredService<IConnectionMultiplexer>();
        var db = redis.GetDatabase();
        var sub = context.HttpContext.User.FindFirst("sub")?.Value ?? "anonymous";
        var redisKey = $"idempotency:{sub}:{idempotencyKey}";

        bool lockAcquired = await db.StringSetAsync(
            redisKey,
            "IN_PROGRESS",
            TimeSpan.FromMinutes(5),
            When.NotExists);

        if (!lockAcquired)
        {
            context.Result = new ConflictObjectResult(new ProblemDetails
            {
                Type = "/errors/idempotency-conflict",
                Title = "Request Already Processed or In Progress",
                Detail = "A request with this Idempotency-Key is currently running or has already been completed.",
                Status = StatusCodes.Status409Conflict
            });
            return;
        }

        try
        {
            var executedContext = await next();

            if (executedContext.Exception is null && IsSuccessfulResult(executedContext.Result))
            {
                await db.StringSetAsync(redisKey, "COMPLETED", TimeSpan.FromHours(24), When.Always);
            }
            else
            {
                await db.KeyDeleteAsync(redisKey);
            }
        }
        catch
        {
            await db.KeyDeleteAsync(redisKey);
            throw;
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
