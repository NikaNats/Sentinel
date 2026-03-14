using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Sentinel.Application.Auth.Interfaces;

namespace Sentinel.Application.Auth.Models;

public sealed class UmaResourceAuthorizationHandler(
    IUmaPermissionService umaService,
    IHttpContextAccessor httpContextAccessor) : AuthorizationHandler<UmaResourceRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, UmaResourceRequirement requirement)
    {
        var httpContext = httpContextAccessor.HttpContext;
        if (httpContext is null)
        {
            return;
        }

        var authHeader = httpContext.Request.Headers.Authorization.ToString();
        var token = ExtractToken(authHeader);
        if (string.IsNullOrWhiteSpace(token))
        {
            context.Fail(new AuthorizationFailureReason(this, "Missing or invalid Authorization header."));
            return;
        }

        var resourceId = httpContext.GetRouteValue("id")?.ToString();
        if (string.IsNullOrWhiteSpace(resourceId))
        {
            context.Fail(new AuthorizationFailureReason(this, "Resource ID missing in route."));
            return;
        }

        var hasAccess = await umaService.HasAccessAsync(token, resourceId, requirement.RequiredScope, httpContext.RequestAborted);
        if (hasAccess)
        {
            context.Succeed(requirement);
            return;
        }

        context.Fail(new AuthorizationFailureReason(this, $"UMA policy evaluation failed for {resourceId}#{requirement.RequiredScope}."));
    }

    private static string? ExtractToken(string? authHeader)
    {
        if (string.IsNullOrWhiteSpace(authHeader))
        {
            return null;
        }

        if (authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
        {
            return authHeader["DPoP ".Length..].Trim();
        }

        if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return authHeader["Bearer ".Length..].Trim();
        }

        return null;
    }
}
