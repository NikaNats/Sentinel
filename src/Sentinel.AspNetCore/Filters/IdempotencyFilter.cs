using Microsoft.AspNetCore.Mvc;
using Sentinel.Security.Abstractions.Exceptions;
using Sentinel.Security.Abstractions.Idempotency;

namespace Sentinel.AspNetCore.Filters;

/// <summary>
///     Native AOT-compatible Endpoint Filter for Redis-backed idempotency.
///     RFC 9110 Section 9.2.2 specifies idempotent requests should not produce
///     multiple side effects. This filter enforces exactly-once semantics by:
///     1. Using Idempotency-Key header to deduplicate requests
///     2. Storing idempotency state in Redis with TTL
///     3. Returning 204 NoContent for duplicates (idempotent retry safety)
/// </summary>
public sealed class IdempotencyFilter(
    IIdempotencyStore idempotencyStore,
    ILogger<IdempotencyFilter> logger) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var httpContext = context.HttpContext;

        if (!httpContext.Request.Headers.TryGetValue("Idempotency-Key", out var keyValues)
            || string.IsNullOrWhiteSpace(keyValues.ToString()))
        {
            return TypedResults.Problem(
                type: "/errors/missing-idempotency-key",
                title: "Idempotency Key Required",
                detail: "The 'Idempotency-Key' header is required for this operation.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var idempotencyKey = keyValues.ToString();

        // Validate idempotency key format (must be UUID or similar)
        if (!IsValidIdempotencyKey(idempotencyKey))
        {
            return TypedResults.Problem(
                type: "/errors/invalid-idempotency-key",
                title: "Invalid Idempotency Key",
                detail: "Idempotency key must be a valid UUID.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var sub = httpContext.User.FindFirst("sub")?.Value ?? "anonymous";
        var storeKey = $"idempotency:{sub}:{idempotencyKey}";

        IdempotencyAcquireResult acquireResult;
        try
        {
            acquireResult = await idempotencyStore.TryAcquireAsync(
                storeKey,
                TimeSpan.FromMinutes(5),
                httpContext.RequestAborted);
        }
        catch (IdempotencyStoreUnavailableException ex)
        {
            logger.LogCritical(ex, "Idempotency store unavailable during idempotency check.");
            return TypedResults.Problem(
                type: "/errors/idempotency-unavailable",
                title: "Idempotency service unavailable",
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        if (acquireResult == IdempotencyAcquireResult.Completed)
        {
            return TypedResults.NoContent();
        }

        if (acquireResult == IdempotencyAcquireResult.InProgress)
        {
            return TypedResults.Conflict(new ProblemDetails
            {
                Type = "/errors/idempotency-conflict",
                Title = "Request In Progress",
                Detail = "A request with this Idempotency-Key is currently running."
            });
        }

        try
        {
            var result = await next(context);

            // If the endpoint succeeded (2xx), mark as COMPLETED
            if (IsSuccessfulResult(result))
            {
                await idempotencyStore.MarkCompletedAsync(
                    storeKey,
                    TimeSpan.FromHours(24),
                    httpContext.RequestAborted);
            }
            else
            {
                await idempotencyStore.ReleaseAsync(storeKey, httpContext.RequestAborted);
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during idempotent operation execution.");
            try
            {
                await idempotencyStore.ReleaseAsync(storeKey, httpContext.RequestAborted);
            }
            catch (IdempotencyStoreUnavailableException cleanupEx)
            {
                logger.LogWarning(cleanupEx,
                    "Idempotency store unavailable while releasing key after request failure.");
            }

            throw;
        }
    }

    private static bool IsValidIdempotencyKey(string key)
    {
        // UUID validation (must be valid UUID4 format)
        return Guid.TryParse(key, out _);
    }

    private static bool IsSuccessfulResult(object? result)
    {
        if (result is IStatusCodeHttpResult statusCodeResult)
        {
            return statusCodeResult.StatusCode is >= 200 and < 300;
        }

        return result is not null;
    }
}
