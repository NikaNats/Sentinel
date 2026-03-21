using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Errors;
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
                Type = ErrorCodes.MissingIdempotencyKey,
                Title = "Idempotency Key Required",
                Detail = $"The '{headerName}' header is required for this operation.",
                Status = StatusCodes.Status400BadRequest
            });
            return;
        }

        var idempotencyKey = keyValues.ToString();
        var logger = context.HttpContext.RequestServices.GetService<ILogger<RequireIdempotencyAttribute>>()
                     ?? NullLogger<RequireIdempotencyAttribute>.Instance;
        var redis = context.HttpContext.RequestServices.GetRequiredService<IConnectionMultiplexer>();
        var db = redis.GetDatabase();
        var sub = context.HttpContext.User.FindFirst("sub")?.Value ?? "anonymous";
        var redisKey = $"idempotency:{sub}:{idempotencyKey}";

        bool lockAcquired;
        try
        {
            lockAcquired = await db.StringSetAsync(
                redisKey,
                "IN_PROGRESS",
                TimeSpan.FromMinutes(5),
                When.NotExists);
        }
        catch (RedisException ex)
        {
            logger.LogCritical(ex, "Redis unavailable during idempotency check.");
            context.Result = BuildUnavailableResult();
            return;
        }

        if (!lockAcquired)
        {
            RedisValue currentState;
            try
            {
                currentState = await db.StringGetAsync(redisKey);
            }
            catch (RedisException ex)
            {
                logger.LogCritical(ex, "Redis unavailable during idempotency state read.");
                context.Result = BuildUnavailableResult();
                return;
            }

            if (string.Equals(currentState.ToString(), "COMPLETED", StringComparison.Ordinal))
            {
                context.Result = new NoContentResult();
                return;
            }

            context.Result = new ConflictObjectResult(new ProblemDetails
            {
                Type = ErrorCodes.IdempotencyConflict,
                Title = "Request In Progress",
                Detail = "A request with this Idempotency-Key is currently running.",
                Status = StatusCodes.Status409Conflict
            });
            return;
        }

        try
        {
            var executedContext = await next();

            if (executedContext.Exception is null && IsSuccessfulResult(executedContext.Result))
            {
                try
                {
                    await db.StringSetAsync(redisKey, "COMPLETED", TimeSpan.FromHours(24), When.Always);
                }
                catch (RedisException ex)
                {
                    logger.LogCritical(ex, "Redis unavailable while marking idempotency request as completed.");
                    executedContext.Result = BuildUnavailableResult();
                }
            }
            else
            {
                try
                {
                    await db.KeyDeleteAsync(redisKey);
                }
                catch (RedisException ex)
                {
                    logger.LogCritical(ex,
                        "Redis unavailable while releasing idempotency lock after unsuccessful request.");
                    executedContext.Result = BuildUnavailableResult();
                }
            }
        }
        catch
        {
            try
            {
                await db.KeyDeleteAsync(redisKey);
            }
            catch (RedisException ex)
            {
                logger.LogCritical(ex, "Redis unavailable while releasing idempotency lock after exception.");
            }

            throw;
        }
    }

    private static ObjectResult BuildUnavailableResult()
    {
        return new ObjectResult(new ProblemDetails
        {
            Type = ErrorCodes.IdempotencyUnavailable,
            Title = "Idempotency service unavailable",
            Status = StatusCodes.Status503ServiceUnavailable
        })
        {
            StatusCode = StatusCodes.Status503ServiceUnavailable
        };
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
