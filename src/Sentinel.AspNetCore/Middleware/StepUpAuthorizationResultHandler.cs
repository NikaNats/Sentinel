using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Sentinel.Application.Auth.Models;
using Sentinel.Security.Abstractions.Options;

namespace Sentinel.AspNetCore.Middleware;

public sealed class StepUpAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly IOptionsMonitor<AcrRankingOptions> acrOptions;
    private readonly AuthorizationMiddlewareResultHandler defaultHandler = new();
    private readonly ILogger<StepUpAuthorizationResultHandler> logger;

    public StepUpAuthorizationResultHandler(
        ILogger<StepUpAuthorizationResultHandler> logger,
        IOptionsMonitor<AcrRankingOptions> acrOptions)
    {
        this.logger = logger;
        this.acrOptions = acrOptions;
    }

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

            acrRequirement ??= ResolveAcrRequirementFromFailure(context, policy, authorizeResult);

            if (acrRequirement is not null)
            {
                var requiredAcr = acrRequirement.MinimumAcr;
                var authHeader = context.Request.Headers.Authorization.ToString();
                var authScheme = authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase)
                    ? "DPoP"
                    : "Bearer";

                var wwwAuthenticateHeader =
                    $"{authScheme} error=\"insufficient_user_authentication\", error_description=\"Step-up authentication required\", acr_values=\"{requiredAcr}\"";

                logger.LogWarning(
                    "security:acr_stepup_triggered required_acr={RequiredAcr} sub={Subject} path={Path}",
                    requiredAcr,
                    context.User.FindFirst("sub")?.Value ?? "unknown",
                    context.Request.Path);

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

    private AcrRequirement? ResolveAcrRequirementFromFailure(
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        var rankings = acrOptions.CurrentValue.Rankings;
        var failureReasons = authorizeResult.AuthorizationFailure?
                                 .FailureReasons
                                 .Select(r => r.Message)
                                 .ToArray()
                             ?? [];

        foreach (var reason in failureReasons)
        {
            if (reason.StartsWith("Insufficient ACR.", StringComparison.Ordinal)
                && reason.Contains("Required:", StringComparison.Ordinal))
            {
                var markerIndex = reason.IndexOf("Required:", StringComparison.Ordinal);
                if (markerIndex >= 0)
                {
                    var requiredAcr = reason[(markerIndex + "Required:".Length)..]
                        .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                        .FirstOrDefault();

                    if (!string.IsNullOrWhiteSpace(requiredAcr))
                    {
                        return new AcrRequirement(requiredAcr);
                    }
                }
            }
        }

        var tokenAcr = context.User.FindFirst("acr")?.Value;
        if (!rankings.TryGetValue(tokenAcr ?? string.Empty, out var tokenRank))
        {
            return null;
        }

        var requiredAcrPolicy = policy.Requirements
            .OfType<AcrRequirement>()
            .OrderByDescending(requirement => rankings.TryGetValue(requirement.MinimumAcr, out var rank) ? rank : 0)
            .FirstOrDefault();

        if (requiredAcrPolicy is null)
        {
            return null;
        }

        return rankings.TryGetValue(requiredAcrPolicy.MinimumAcr, out var requiredRank)
               && tokenRank < requiredRank
            ? requiredAcrPolicy
            : null;
    }
}
