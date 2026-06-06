using Microsoft.AspNetCore.Mvc;
using Sentinel.Security.Abstractions.Exceptions;
using Sentinel.Security.Abstractions.Idempotency;

namespace Sentinel.AspNetCore.Filters;

/// <summary>
///     Native AOT-compatible Endpoint Filter for Redis-backed idempotency.
///     Caches the exact HTTP response bytes to ensure Stripe-style REST semantics.
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
        if (!Guid.TryParse(idempotencyKey, out _))
        {
            return TypedResults.Problem(
                type: "/errors/invalid-idempotency-key",
                title: "Invalid Idempotency Key",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var sub = httpContext.User.FindFirst("sub")?.Value ?? "anonymous";
        var storeKey = $"idempotency:{sub}:{idempotencyKey}";

        try
        {
            var (state, cachedResponse) = await idempotencyStore.TryAcquireAsync(
                storeKey,
                TimeSpan.FromMinutes(5),
                httpContext.RequestAborted);

            if (state == IdempotencyAcquireResult.Completed)
            {
                if (cachedResponse is not null)
                {
                    return new IdempotencyReplayResult(cachedResponse);
                }

                return TypedResults.NoContent();
            }

            if (state == IdempotencyAcquireResult.InProgress)
            {
                return TypedResults.Conflict(new ProblemDetails
                {
                    Type = "/errors/idempotency-conflict",
                    Title = "Request In Progress",
                    Detail = "A request with this Idempotency-Key is currently running."
                });
            }

            var result = await next(context);

            if (result is IResult iresult)
            {
                return new IdempotencySaveResult(iresult, idempotencyStore, storeKey, TimeSpan.FromHours(24), logger);
            }

            await idempotencyStore.ReleaseAsync(storeKey, httpContext.RequestAborted);
            return result;
        }
        catch (IdempotencyStoreUnavailableException ex)
        {
            logger.LogCritical(ex, "Idempotency store unavailable.");
            return TypedResults.Problem(
                type: "/errors/idempotency-unavailable",
                title: "Idempotency service unavailable",
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }
    }
}

internal sealed class IdempotencyReplayResult(CachedHttpResponse cachedResponse) : IResult
{
    public async Task ExecuteAsync(HttpContext httpContext)
    {
        httpContext.Response.StatusCode = cachedResponse.StatusCode;
        if (!string.IsNullOrEmpty(cachedResponse.ContentType))
        {
            httpContext.Response.ContentType = cachedResponse.ContentType;
        }

        await httpContext.Response.Body.WriteAsync(cachedResponse.Body, httpContext.RequestAborted);
    }
}

internal sealed class IdempotencySaveResult(
    IResult innerResult,
    IIdempotencyStore store,
    string storeKey,
    TimeSpan ttl,
    ILogger logger) : IResult
{
    public async Task ExecuteAsync(HttpContext httpContext)
    {
        var originalBodyStream = httpContext.Response.Body;
        using var memoryStream = new MemoryStream();
        httpContext.Response.Body = memoryStream;

        try
        {
            await innerResult.ExecuteAsync(httpContext);

            var statusCode = httpContext.Response.StatusCode;

            if (statusCode is >= 200 and < 300)
            {
                memoryStream.Seek(0, SeekOrigin.Begin);
                var bodyBytes = memoryStream.ToArray();
                var contentType = httpContext.Response.ContentType ?? "application/json";

                var cachedResponse = new CachedHttpResponse(statusCode, contentType, bodyBytes);

                await store.MarkCompletedAsync(storeKey, cachedResponse, ttl, httpContext.RequestAborted);
            }
            else
            {
                await store.ReleaseAsync(storeKey, httpContext.RequestAborted);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error executing idempotent result");
            try
            {
                await store.ReleaseAsync(storeKey, httpContext.RequestAborted);
            }
            catch (IdempotencyStoreUnavailableException)
            {
            }

            throw;
        }
        finally
        {
            httpContext.Response.Body = originalBodyStream;
            memoryStream.Seek(0, SeekOrigin.Begin);
            await memoryStream.CopyToAsync(originalBodyStream, httpContext.RequestAborted);
        }
    }
}
