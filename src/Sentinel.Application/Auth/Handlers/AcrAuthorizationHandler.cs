using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Sentinel.Application.Auth.Models;
using Sentinel.Security.Abstractions.Options;

namespace Sentinel.Application.Auth.Handlers;

/// <summary>
/// Authorization handler for ACR (Authentication Context Class Reference) validation.
/// Implements hierarchical assurance level enforcement per NIST AAL3.
/// Example: ACR3 satisfies ACR2 requirement; ACR1 does not.
/// </summary>
public sealed class AcrAuthorizationHandler : AuthorizationHandler<AcrRequirement>
{
    private readonly IOptionsMonitor<AcrRankingOptions> options;

    public AcrAuthorizationHandler(IOptionsMonitor<AcrRankingOptions> options)
    {
        this.options = options;
    }

    /// <summary>
    /// Validates user's ACR against requirement using ranking system.
    /// User's rank must be equal to or greater than required rank.
    /// </summary>
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AcrRequirement requirement)
    {
        var userAcr = context.User.FindFirst("acr")?.Value;
        if (string.IsNullOrWhiteSpace(userAcr))
        {
            return Task.CompletedTask;
        }

        var rankings = options.CurrentValue.Rankings;

        // Ensure both the user's ACR and required ACR exist in rankings
        if (!rankings.TryGetValue(userAcr, out var userRank))
        {
            return Task.CompletedTask;
        }

        if (!rankings.TryGetValue(requirement.MinimumAcr, out var requiredRank))
        {
            return Task.CompletedTask;
        }

        // User's rank must be >= required rank (higher rank = stronger assurance)
        if (userRank >= requiredRank)
        {
            context.Succeed(requirement);
        }
        else
        {
            context.Fail(new AuthorizationFailureReason(
                this,
                $"Insufficient ACR. Required: {requirement.MinimumAcr}, User ACR: {userAcr}"));
        }

        return Task.CompletedTask;
    }
}
    }
}
