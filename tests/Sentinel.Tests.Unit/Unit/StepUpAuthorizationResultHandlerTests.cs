using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
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
using Xunit;

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

    [Fact(DisplayName = "Scenario 1: Failed AcrRequirement returns FAPI compliant Step-Up challenge")]
    public async Task HandleAsync_WhenForbiddenDueToAcrRequirement_ReturnsStepUpChallenge()
    {
        var acrOptions = CreateAcrOptionsMonitor();
        var sut = new StepUpAuthorizationResultHandler(NullLogger<StepUpAuthorizationResultHandler>.Instance,
            acrOptions);
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "DPoP test-token";
        context.Response.Body = new MemoryStream();

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

    [Fact(DisplayName = "Scenario 2: Forbidden for other reasons uses default handler")]
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

    [Fact(DisplayName = "Scenario 3: Successfully parses and extracts required ACR from raw text failure reasons")]
    public async Task HandleAsync_WithTextFailureReason_ParsesAndReturnsStepUpChallenge()
    {
        var acrOptions = CreateAcrOptionsMonitor();
        var sut = new StepUpAuthorizationResultHandler(NullLogger<StepUpAuthorizationResultHandler>.Instance, acrOptions);
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "Bearer test-token";
        context.Response.Body = new MemoryStream();

        var policy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();

        var failureReason = new AuthorizationFailureReason(new Mock<IAuthorizationHandler>().Object, "Insufficient ACR. Required: acr3");
        var failure = AuthorizationFailure.Failed(new[] { failureReason });
        var authorizeResult = PolicyAuthorizationResult.Forbid(failure);

        await sut.HandleAsync(_ => Task.CompletedTask, context, policy, authorizeResult);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        var header = context.Response.Headers.WWWAuthenticate.ToString();
        Assert.Contains("Bearer", header, StringComparison.Ordinal);
        Assert.Contains("insufficient_user_authentication", header, StringComparison.Ordinal);
        Assert.Contains("acr_values=\"acr3\"", header, StringComparison.Ordinal);
    }

    [Theory(DisplayName = "Scenario 4: Hierarchical ACR ranking successfully selects the highest failed ACR level")]
    [InlineData("acr1", "acr3")]
    [InlineData("acr2", "acr3")]
    public async Task HandleAsync_WithMultipleAcrRequirements_SelectsHighestFailedAcr(string userAcr, string expectedRequiredAcr)
    {
        var acrOptions = CreateAcrOptionsMonitor();
        var sut = new StepUpAuthorizationResultHandler(NullLogger<StepUpAuthorizationResultHandler>.Instance, acrOptions);
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "DPoP test-token";
        context.Response.Body = new MemoryStream();

        context.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("acr", userAcr) }, "Bearer"));

        var policy = new AuthorizationPolicyBuilder()
            .AddRequirements(new AcrRequirement("acr2"))
            .AddRequirements(new AcrRequirement("acr3"))
            .Build();

        var failure = AuthorizationFailure.Failed(new[] { new ScopeRequirement("dummy-scope") });
        var authorizeResult = PolicyAuthorizationResult.Forbid(failure);

        await sut.HandleAsync(_ => Task.CompletedTask, context, policy, authorizeResult);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        var header = context.Response.Headers.WWWAuthenticate.ToString();
        Assert.Contains($"acr_values=\"{expectedRequiredAcr}\"", header, StringComparison.Ordinal);
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
