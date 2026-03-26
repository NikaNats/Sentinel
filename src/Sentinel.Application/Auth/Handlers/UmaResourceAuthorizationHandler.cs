using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;

namespace Sentinel.Application.Auth.Handlers;

/// <summary>
/// Authorization handler for UMA 2.0 (User-Managed Access) resource permissions.
/// Validates resource access through Keycloak UMA permission endpoint.
/// </summary>
public sealed class UmaResourceAuthorizationHandler : AuthorizationHandler<UmaResourceRequirement>
{
    private readonly IUmaPermissionService permissionService;
    private readonly IHttpContextAccessor httpContextAccessor;

    public UmaResourceAuthorizationHandler(
        IUmaPermissionService permissionService,
        IHttpContextAccessor httpContextAccessor)
    {
        this.permissionService = permissionService;
        this.httpContextAccessor = httpContextAccessor;
    }

    /// <summary>
    /// Validates resource access using UMA permission endpoint.
    /// Extracts access token from Authorization header and resource ID from route values.
    /// </summary>
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        UmaResourceRequirement requirement)
    {
        var httpContext = httpContextAccessor.HttpContext;
        if (httpContext?.Request == null)
        {
            return;
        }

        // Extract access token from Authorization header
        var authHeader = httpContext.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authHeader))
        {
            return;
        }

        var token = ExtractToken(authHeader);
        if (string.IsNullOrWhiteSpace(token))
        {
            return;
        }

        // Extract resource ID from route values
        if (!httpContext.Request.RouteValues.TryGetValue("id", out var resourceIdObj))
        {
            return;
        }

        var resourceId = resourceIdObj?.ToString();
        if (string.IsNullOrWhiteSpace(resourceId))
        {
            return;
        }

        // Check UMA permission
        var hasAccess = await permissionService.HasAccessAsync(
            token,
            resourceId,
            requirement.RequiredScope,
            context.Resource as CancellationToken ?? CancellationToken.None);

        if (hasAccess)
        {
            context.Succeed(requirement);
        }
    }

    /// <summary>
    /// Extracts bearer token from Authorization header, handling both "Bearer" and "DPoP" schemes.
    /// </summary>
    private static string ExtractToken(string authHeader)
    {
        const string bearerPrefix = "Bearer ";
        const string dpopPrefix = "DPoP ";

        if (authHeader.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return authHeader.Substring(bearerPrefix.Length).Trim();
        }

        if (authHeader.StartsWith(dpopPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return authHeader.Substring(dpopPrefix.Length).Trim();
        }

        return string.Empty;
    }
}
