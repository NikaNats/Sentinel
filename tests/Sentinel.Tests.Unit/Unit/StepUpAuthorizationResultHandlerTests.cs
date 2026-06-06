using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.Application.Auth.Models;
using Sentinel.AspNetCore.Middleware;
using Sentinel.Security.Abstractions.Options;

namespace Sentinel.Tests.Unit.Unit;

public sealed class StepUpAuthorizationResultHandlerTests
{
    private static IOptionsMonitor<AcrRankingOptions> CreateAcrOptionsMonitor()
    {
        var options = new AcrRankingOptions();
        var mockMonitor = new Mock<IOptionsMonitor<AcrRankingOptions>>();
        mockMonitor.Setup(m => m.CurrentValue).Returns(options);
        return mockMonitor.Object;
    }

    [Fact]
    public async Task HandleAsync_WhenForbiddenDueToAcrRequirement_ReturnsStepUpChallenge()
    {
        var acrOptions = CreateAcrOptionsMonitor();
        var sut = new StepUpAuthorizationResultHandler(NullLogger<StepUpAuthorizationResultHandler>.Instance,
            acrOptions);
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "DPoP test-token";

        var policy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
        var failure = AuthorizationFailure.Failed([new AcrRequirement("acr3")]);
        var authorizeResult = PolicyAuthorizationResult.Forbid(failure);

        await sut.HandleAsync(_ => Task.CompletedTask, context, policy, authorizeResult);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        var header = context.Response.Headers.WWWAuthenticate.ToString();
        Assert.Contains("DPoP", header, StringComparison.Ordinal);
        Assert.Contains("insufficient_user_authentication", header, StringComparison.Ordinal);
        Assert.Contains("acr_values=\"acr3\"", header, StringComparison.Ordinal);
    }

    [Fact]
    public async Task HandleAsync_WhenForbiddenForOtherReason_UsesDefaultHandler()
    {
        var acrOptions = CreateAcrOptionsMonitor();
        var sut = new StepUpAuthorizationResultHandler(NullLogger<StepUpAuthorizationResultHandler>.Instance,
            acrOptions);
        var context = new DefaultHttpContext();
        var services = new ServiceCollection()
            .AddSingleton<IAuthenticationService, FakeAuthenticationService>()
            .BuildServiceProvider();
        context.RequestServices = services;

        var policy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();

        var failure = AuthorizationFailure.Failed([new ScopeRequirement("document:read")]);
        var authorizeResult = PolicyAuthorizationResult.Forbid(failure);

        await sut.HandleAsync(_ => Task.CompletedTask, context, policy, authorizeResult);

        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    private sealed class FakeAuthenticationService : IAuthenticationService
    {
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) =>
            Task.FromResult(AuthenticateResult.NoResult());

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }

        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal,
            AuthenticationProperties? properties) =>
            Task.CompletedTask;

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
            Task.CompletedTask;
    }
}
