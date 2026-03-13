using Microsoft.AspNetCore.Mvc;
using Sentinel.Infrastructure.Auth;
using Sentinel.Infrastructure.Cache;

namespace Sentinel.Middleware;

public sealed class DpopValidationMiddleware(RequestDelegate next, IDpopProofValidator validator)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.Headers.Append("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\", algs=\"PS256 ES256\"");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }

            await next(context);
            return;
        }

        var dpopProof = context.Request.Headers["DPoP"].ToString();
        if (string.IsNullOrWhiteSpace(dpopProof))
        {
            context.Response.Headers.Append("WWW-Authenticate", "DPoP error=\"missing_dpop_proof\"");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var token = authHeader["DPoP ".Length..].Trim();
        var requestUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}";

        DpopValidationResult result;
        try
        {
            result = await validator.ValidateAsync(dpopProof, token, context.Request.Method, requestUrl, context.RequestAborted);
        }
        catch (ReplayCacheUnavailableException)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await context.Response.WriteAsJsonAsync(new ProblemDetails
            {
                Type = "/errors/replay-cache-unavailable",
                Title = "Security subsystem unavailable",
                Detail = "DPoP replay protection is temporarily unavailable.",
                Status = StatusCodes.Status503ServiceUnavailable
            });
            return;
        }

        if (!result.IsValid)
        {
            context.Response.Headers.Append("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\", algs=\"PS256 ES256\"");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        context.Response.Headers.Append("DPoP-Nonce", result.NewNonce);
        await next(context);
    }
}
