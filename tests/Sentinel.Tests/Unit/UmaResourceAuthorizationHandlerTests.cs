using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Moq;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using System.Security.Claims;

namespace Sentinel.Tests.Unit;

public sealed class UmaResourceAuthorizationHandlerTests
{
    [Fact]
    public async Task HandleRequirementAsync_WhenUmaPermits_Succeeds()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = "DPoP token-value";
        httpContext.Request.RouteValues["id"] = "document-123";

        var accessor = new HttpContextAccessor { HttpContext = httpContext };

        var umaService = new Mock<IUmaPermissionService>();
        umaService
            .Setup(x => x.HasAccessAsync("token-value", "document-123", "document:read", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var requirement = new UmaResourceRequirement("document:read");
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-1")], "test"));
        var context = new AuthorizationHandlerContext([requirement], user, null);

        var handler = new UmaResourceAuthorizationHandler(umaService.Object, accessor);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleRequirementAsync_WhenRouteIdMissing_Fails()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = "Bearer token-value";

        var accessor = new HttpContextAccessor { HttpContext = httpContext };
        var umaService = new Mock<IUmaPermissionService>();

        var requirement = new UmaResourceRequirement("document:delete");
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-1")], "test"));
        var context = new AuthorizationHandlerContext([requirement], user, null);

        var handler = new UmaResourceAuthorizationHandler(umaService.Object, accessor);

        await handler.HandleAsync(context);

        Assert.True(context.HasFailed);
        Assert.False(context.HasSucceeded);
    }
}
