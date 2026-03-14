using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Application.Auth.Models;

namespace Sentinel.Middleware;

public sealed class StepUpAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler defaultHandler = new();

    public async Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        if (authorizeResult.Challenged || authorizeResult.Forbidden)
        {
            var acrRequirement = authorizeResult.AuthorizationFailure?
                .FailedRequirements
                .OfType<AcrRequirement>()
                .FirstOrDefault();

            if (acrRequirement is not null)
            {
                var requiredAcr = acrRequirement.MinimumAcr;
                var authHeader = context.Request.Headers.Authorization.ToString();
                var authScheme = authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase)
                    ? "DPoP"
                    : "Bearer";

                var wwwAuthenticateHeader =
                    $"{authScheme} error=\"insufficient_user_authentication\", error_description=\"Step-up authentication required\", acr_values=\"{requiredAcr}\"";

                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.Append("WWW-Authenticate", wwwAuthenticateHeader);

                await context.Response.WriteAsJsonAsync(new ProblemDetails
                {
                    Type = "/errors/insufficient-acr",
                    Title = "Step-up Authentication Required",
                    Detail = $"This endpoint requires '{requiredAcr}'. Please re-authenticate.",
                    Status = StatusCodes.Status401Unauthorized,
                    Extensions =
                    {
                        ["required_acr"] = requiredAcr
                    }
                });

                return;
            }
        }

        await defaultHandler.HandleAsync(next, context, policy, authorizeResult);
    }
}
