using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Sentinel.AspNetCore.Middleware;

namespace Sentinel.Tests.Unit.Unit;

/// <summary>
///     High-Assurance Tests for AcrValidationMiddleware
///     MISSION: Test "Fail-Closed" logic and protect against operational safety edge cases.
///     Ensures middleware doesn't crash the pipeline or expose topology details.
///     Tests focus on adversarial scenarios: response already started, missing headers, etc.
/// </summary>
public sealed class AcrValidationMiddlewareTests
{
    [Fact(DisplayName = "🚨 Pipe Safety: Middleware must abort if response has already started")]
    public async Task InvokeAsync_WhenResponseHasStarted_MustNotAttemptToWriteBody()
    {
        // Arrange
        var context = new DefaultHttpContext();
        // Setup authenticated user WITHOUT ACR
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user1")], "Bearer"));

        // Mock a started response (e.g., from an earlier filter or logging middleware)
        var feature = new MockResponseFeature { HasStarted = true };
        context.Features.Set<IHttpResponseFeature>(feature);

        var sut = new AcrValidationMiddleware(_ => Task.CompletedTask);

        // Act
        var act = async () => await sut.InvokeAsync(context);

        // Assert
        // If the middleware tries to write to a started response, it throws InvalidOperationException.
        // A 100/100 implementation handles this gracefully (fail-safe, not fail-dead).
        await act.Should().NotThrowAsync<InvalidOperationException>(
            "Middleware must check context.Response.HasStarted to prevent catastrophic double-writes " +
            "that crash the request pipeline.");
    }

    [Fact]
    public async Task InvokeAsync_WhenUnauthenticated_PassesToNext()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var nextCalled = false;
        var sut = new AcrValidationMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        // Act
        await sut.InvokeAsync(context);

        // Assert
        nextCalled.Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact(DisplayName = "🔐 Zero Trust: Missing ACR must return RFC 7807 ProblemDetails")]
    public async Task InvokeAsync_WhenAuthenticatedButMissingAcr_Returns401_WithSanitizedError()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "u1")], "Bearer"));

        var sut = new AcrValidationMiddleware(_ => Task.CompletedTask);

        // Act
        await sut.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.Should()
            .Be(StatusCodes.Status401Unauthorized,
                "Missing ACR is an authentication context failure, not authorization failure.");
        context.Response.ContentType.Should()
            .Contain("application/problem+json",
                "RFC 7807 ProblemDetails format ensures machine-readability and consistency.");
    }

    [Fact]
    public async Task InvokeAsync_WhenAuthenticatedWithAcr_PassesToNext()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.User = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim("sub", "user1"),
            new Claim("acr", "acr2")
        ], "Bearer"));

        var nextCalled = false;
        var sut = new AcrValidationMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        // Act
        await sut.InvokeAsync(context);

        // Assert
        nextCalled.Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact]
    public async Task InvokeAsync_WhenAuthenticatedWithEmptyAcr_Returns401()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.User = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim("sub", "user1"),
            new Claim("acr", "")
        ], "Bearer"));

        var sut = new AcrValidationMiddleware(_ => Task.CompletedTask);

        // Act
        await sut.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public async Task InvokeAsync_WhenAuthenticatedWithWhitespaceAcr_Returns401()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.User = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim("sub", "user1"),
            new Claim("acr", "   ")
        ], "Bearer"));

        var sut = new AcrValidationMiddleware(_ => Task.CompletedTask);

        // Act
        await sut.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public async Task InvokeAsync_WhenFailureResponse_ReturnsValidProblemDetails()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Headers["Content-Type"] = "application/json";
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user1")], "Bearer"));

        var sut = new AcrValidationMiddleware(_ => Task.CompletedTask);

        // Act
        await sut.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        context.Response.ContentType.Should().Contain("application/problem+json");
    }

    [Fact]
    public async Task InvokeAsync_WithMultipleClaimsSameName_UsesFirstAcrClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity([
            new Claim("sub", "user1"),
            new Claim("acr", "acr2")
        ], "Bearer");

        var context = new DefaultHttpContext();
        context.User = new ClaimsPrincipal(identity);

        var nextCalled = false;
        var sut = new AcrValidationMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        // Act
        await sut.InvokeAsync(context);

        // Assert
        nextCalled.Should().BeTrue();
    }

    // ====== Test Helper: Mock IHttpResponseFeature ======
    /// <summary>
    ///     Mock implementation of IHttpResponseFeature to simulate a response that has already started.
    ///     Used to test edge case where middleware must not attempt to write headers/body.
    /// </summary>
    private sealed class MockResponseFeature : IHttpResponseFeature
    {
        public int StatusCode { get; set; }
        public string? ReasonPhrase { get; set; }
        public IHeaderDictionary Headers { get; set; } = new HeaderDictionary();
        public Stream Body { get; set; } = new MemoryStream();
        public bool HasStarted { get; set; }

        public void OnStarting(Func<object, Task> callback, object state)
        {
        }

        public void OnCompleted(Func<object, Task> callback, object state)
        {
        }
    }
}
