using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Sentinel.Application.Auth.Models;
using Sentinel.Security.Abstractions.Options;

namespace Sentinel.Auth.Authorization;

public sealed class AcrAuthorizationHandler : AuthorizationHandler<AcrRequirement>
{
    private readonly IOptionsMonitor<AcrRankingOptions> acrOptions;

    public AcrAuthorizationHandler(IOptionsMonitor<AcrRankingOptions> acrOptions)
    {
        this.acrOptions = acrOptions;
    }

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AcrRequirement requirement)
    {
        var rankings = acrOptions.CurrentValue.Rankings;
        var tokenAcr = context.User.FindFirst("acr")?.Value;

        if (string.IsNullOrWhiteSpace(tokenAcr)
            || !rankings.TryGetValue(tokenAcr, out var tokenRank)
            || !rankings.TryGetValue(requirement.MinimumAcr, out var requiredRank)
            || tokenRank < requiredRank)
        {
            context.Fail(new AuthorizationFailureReason(this,
                $"Insufficient ACR. Required: {requirement.MinimumAcr}, Got: {tokenAcr}"));
            return Task.CompletedTask;
        }

        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
