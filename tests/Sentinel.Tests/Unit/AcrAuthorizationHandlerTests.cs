using Microsoft.AspNetCore.Authorization;
using Sentinel.Application.Auth.Models;
using System.Security.Claims;

namespace Sentinel.Tests.Unit;

public sealed class AcrAuthorizationHandlerTests
{
    [Fact]
    public async Task HandleRequirementAsync_WhenTokenAcrMeetsMinimum_Succeeds()
    {
        var handler = new AcrAuthorizationHandler();
        var requirement = new AcrRequirement("acr2");
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("acr", "acr3")], "test"));
        var context = new AuthorizationHandlerContext([requirement], user, null);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleRequirementAsync_WhenTokenAcrBelowMinimum_Fails()
    {
        var handler = new AcrAuthorizationHandler();
        var requirement = new AcrRequirement("acr3");
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("acr", "acr1")], "test"));
        var context = new AuthorizationHandlerContext([requirement], user, null);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
        Assert.True(context.HasFailed);
    }
}
