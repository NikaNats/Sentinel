using Microsoft.AspNetCore.Authorization;

namespace Sentinel.Application.Auth.Models;

public sealed class AcrAuthorizationHandler : AuthorizationHandler<AcrRequirement>
{
    private static readonly Dictionary<string, int> AcrRank = new(StringComparer.OrdinalIgnoreCase)
    {
        ["acr1"] = 1,
        ["acr2"] = 2,
        ["acr3"] = 3
    };

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AcrRequirement requirement)
    {
        var tokenAcr = context.User.FindFirst("acr")?.Value;

        if (string.IsNullOrWhiteSpace(tokenAcr)
            || !AcrRank.TryGetValue(tokenAcr, out var tokenRank)
            || !AcrRank.TryGetValue(requirement.MinimumAcr, out var requiredRank)
            || tokenRank < requiredRank)
        {
            context.Fail(new AuthorizationFailureReason(this, $"Insufficient ACR. Required: {requirement.MinimumAcr}, Got: {tokenAcr}"));
            return Task.CompletedTask;
        }

        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
