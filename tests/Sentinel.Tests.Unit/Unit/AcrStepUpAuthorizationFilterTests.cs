using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Sentinel.AspNetCore.Filters;
using Xunit;

namespace Sentinel.Tests.Unit.Unit;

/// <summary>
///     High-assurance unit tests for AcrStepUpAuthorizationFilter.
///     Validates NIST SP 800-63B step-up requirements, authentication recency (auth_time),
///     and strict RFC 6750 WWW-Authenticate header generation.
/// </summary>
public sealed class AcrStepUpAuthorizationFilterTests
{
    private readonly FakeTimeProvider _timeProvider;
    private readonly TimeSpan _maxAuthAge;
    private readonly AcrStepUpAuthorizationFilter _sut;

    public AcrStepUpAuthorizationFilterTests()
    {
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        _maxAuthAge = TimeSpan.FromMinutes(5);
        _sut = new AcrStepUpAuthorizationFilter("acr3", _maxAuthAge);
    }

    [Fact(DisplayName = "❌ Step-Up: Unauthenticated request must return 401 Unauthorized instantly")]
    public async Task InvokeAsync_UnauthenticatedUser_ReturnsUnauthorized()
    {
        // Arrange
        var context = CreateFilterContext(isAuthenticated: false);

        // Act
        var result = await _sut.InvokeAsync(context, _ => ValueTask.FromResult<object?>(null));

        // Assert
        result.Should().BeOfType<UnauthorizedHttpResult>();
    }

    [Fact(DisplayName = "🔴 Step-Up: Token with insufficient ACR (acr2) must return 401 ProblemDetails with RFC 6750 challenge")]
    public async Task InvokeAsync_InsufficientAcr_ReturnsProblemResultWithChallenge()
    {
        // Arrange
        var context = CreateFilterContext(isAuthenticated: true, acr: "acr2", authTime: _timeProvider.GetUtcNow().ToUnixTimeSeconds());

        // Act
        var result = await _sut.InvokeAsync(context, _ => ValueTask.FromResult<object?>(null));

        // Assert
        var problem = result.Should().BeOfType<ProblemHttpResult>().Subject;
        problem.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        problem.ProblemDetails.Type.Should().Be("/errors/insufficient-acr");

        var responseHeaders = context.HttpContext.Response.Headers;
        responseHeaders.Should().ContainKey("WWW-Authenticate");
        responseHeaders.WWWAuthenticate.ToString().Should().Contain("error=\"insufficient_user_authentication\"");
        responseHeaders.WWWAuthenticate.ToString().Should().Contain("acr_values=\"acr3\"");
        responseHeaders.WWWAuthenticate.ToString().Should().Contain($"max_age=\"{(int)_maxAuthAge.TotalSeconds}\"");
    }

    [Fact(DisplayName = "🔴 Step-Up: Missing auth_time claim in token must fail closed and return 401")]
    public async Task InvokeAsync_MissingAuthTime_ReturnsUnauthorized()
    {
        // Arrange
        var context = CreateFilterContext(isAuthenticated: true, acr: "acr3", authTime: null);

        // Act
        var result = await _sut.InvokeAsync(context, _ => ValueTask.FromResult<object?>(null));

        // Assert
        result.Should().BeOfType<UnauthorizedHttpResult>();
    }

    [Fact(DisplayName = "🔴 Step-Up: Malformed non-numeric auth_time claim must fail closed and return 401")]
    public async Task InvokeAsync_MalformedAuthTime_ReturnsUnauthorized()
    {
        // Arrange
        var context = CreateFilterContext(isAuthenticated: true, acr: "acr3", authTimeStr: "invalid-timestamp");

        // Act
        var result = await _sut.InvokeAsync(context, _ => ValueTask.FromResult<object?>(null));

        // Assert
        result.Should().BeOfType<UnauthorizedHttpResult>();
    }

    [Fact(DisplayName = "⏱️ Step-Up: Stale authentication (auth_time > maxAuthAge) must return 401 ProblemDetails with challenge")]
    public async Task InvokeAsync_ExpiredAuthTime_ReturnsProblemResultWithChallenge()
    {
        // Arrange
        var staleAuthTime = _timeProvider.GetUtcNow().AddSeconds(-301).ToUnixTimeSeconds();
        var context = CreateFilterContext(isAuthenticated: true, acr: "acr3", authTime: staleAuthTime);

        // Act
        var result = await _sut.InvokeAsync(context, _ => ValueTask.FromResult<object?>(null));

        // Assert
        var problem = result.Should().BeOfType<ProblemHttpResult>().Subject;
        problem.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        problem.ProblemDetails.Type.Should().Be("/errors/session-too-old");

        var responseHeaders = context.HttpContext.Response.Headers;
        responseHeaders.WWWAuthenticate.ToString().Should().Contain("error=\"insufficient_user_authentication\"");
        responseHeaders.WWWAuthenticate.ToString().Should().Contain("acr_values=\"acr3\"");
    }

    [Fact(DisplayName = "✅ Step-Up: Valid ACR and recent authentication (auth_time < maxAuthAge) successfully allows execution")]
    public async Task InvokeAsync_ValidAcrAndRecentAuth_CallsNext()
    {
        // Arrange
        var recentAuthTime = _timeProvider.GetUtcNow().AddMinutes(-2).ToUnixTimeSeconds();
        var context = CreateFilterContext(isAuthenticated: true, acr: "acr3", authTime: recentAuthTime);

        var nextCalled = false;
        EndpointFilterDelegate next = _ =>
        {
            nextCalled = true;
            return ValueTask.FromResult<object?>(TypedResults.Ok());
        };

        // Act
        var result = await _sut.InvokeAsync(context, next);

        // Assert
        nextCalled.Should().BeTrue();
        result.Should().BeOfType<Ok>();
    }

    // --- Mocks და სატესტო კონტექსტის დამზადება ---

    // ✅ შესწორებულია: მეთოდის ტიპი შეცვლილია კონკრეტული TestEndpointFilterInvocationContext-ით
    private TestEndpointFilterInvocationContext CreateFilterContext(
        bool isAuthenticated,
        string? acr = null,
        long? authTime = null,
        string? authTimeStr = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddSingleton<ILogger<AcrStepUpAuthorizationFilter>>(NullLogger<AcrStepUpAuthorizationFilter>.Instance);
        var serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext { RequestServices = serviceProvider };

        if (isAuthenticated)
        {
            var claims = new List<Claim> { new Claim("sub", "user-uuid-12345") };

            if (!string.IsNullOrEmpty(acr))
            {
                claims.Add(new Claim("acr", acr));
            }

            if (authTime.HasValue)
            {
                claims.Add(new Claim("auth_time", authTime.Value.ToString(CultureInfo.InvariantCulture)));
            }
            else if (!string.IsNullOrEmpty(authTimeStr))
            {
                claims.Add(new Claim("auth_time", authTimeStr));
            }

            var identity = new ClaimsIdentity(claims, "Bearer");
            httpContext.User = new ClaimsPrincipal(identity);
        }
        else
        {
            httpContext.User = new ClaimsPrincipal(new ClaimsIdentity());
        }

        return new TestEndpointFilterInvocationContext(httpContext);
    }

    private sealed class TestEndpointFilterInvocationContext : EndpointFilterInvocationContext
    {
        private readonly object?[] _arguments = [];

        public TestEndpointFilterInvocationContext(HttpContext httpContext)
        {
            HttpContext = httpContext;
        }

        public override HttpContext HttpContext { get; }
        public override IList<object?> Arguments => _arguments;

        public override T GetArgument<T>(int index) => (T)_arguments[index]!;
    }
}
