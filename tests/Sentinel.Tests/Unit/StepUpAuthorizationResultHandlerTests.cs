using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Application.Auth.Models;
using Sentinel.Middleware;
using System.Security.Claims;

namespace Sentinel.Tests.Unit;

public sealed class StepUpAuthorizationResultHandlerTests
{
    [Fact]
    public async Task HandleAsync_WhenForbiddenDueToAcrRequirement_ReturnsStepUpChallenge()
    {
        var sut = new StepUpAuthorizationResultHandler();
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
        var sut = new StepUpAuthorizationResultHandler();
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
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

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

        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
        {
            return Task.CompletedTask;
        }

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            return Task.CompletedTask;
        }
    }
}
