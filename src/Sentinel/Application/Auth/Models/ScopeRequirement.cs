using Microsoft.AspNetCore.Authorization;

namespace Sentinel.Application.Auth.Models;

public sealed class ScopeRequirement(string requiredScope) : IAuthorizationRequirement
{
    public string RequiredScope { get; } = requiredScope;
}

public sealed class ScopeAuthorizationHandler : AuthorizationHandler<ScopeRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ScopeRequirement requirement)
    {
        var scopeClaim = context.User.FindFirst("scope")?.Value;
        if (string.IsNullOrWhiteSpace(scopeClaim))
        {
            context.Fail(new AuthorizationFailureReason(this, "Missing scope claim."));
            return Task.CompletedTask;
        }

        var scopes = scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (scopes.Contains(requirement.RequiredScope, StringComparer.Ordinal))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        context.Fail(new AuthorizationFailureReason(this, $"Missing required scope '{requirement.RequiredScope}'."));
        return Task.CompletedTask;
    }
}
