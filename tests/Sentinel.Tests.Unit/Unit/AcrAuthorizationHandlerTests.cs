using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.Application.Auth.Models;
using Sentinel.Auth.Authorization;
using Sentinel.Security.Abstractions.Options;

namespace Sentinel.Tests.Unit;

public sealed class AcrAuthorizationHandlerTests
{
    private static IOptionsMonitor<AcrRankingOptions> CreateAcrOptionsMonitor()
    {
        var options = new AcrRankingOptions();
        var mockMonitor = new Mock<IOptionsMonitor<AcrRankingOptions>>();
        mockMonitor.Setup(m => m.CurrentValue).Returns(options);
        return mockMonitor.Object;
    }

    [Fact]
    public async Task HandleRequirementAsync_WhenTokenAcrMeetsMinimum_Succeeds()
    {
        var acrOptions = CreateAcrOptionsMonitor();
        var handler = new AcrAuthorizationHandler(acrOptions);
        var requirement = new AcrRequirement("acr2");
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("acr", "acr3")], "test"));
        var context = new AuthorizationHandlerContext([requirement], user, null);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleRequirementAsync_WhenTokenAcrBelowMinimum_Fails()
    {
        var acrOptions = CreateAcrOptionsMonitor();
        var handler = new AcrAuthorizationHandler(acrOptions);
        var requirement = new AcrRequirement("acr3");
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("acr", "acr1")], "test"));
        var context = new AuthorizationHandlerContext([requirement], user, null);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
        Assert.True(context.HasFailed);
    }
}
