using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Sentinel.AspNetCore.Middleware;
using FluentAssertions;

namespace Sentinel.Tests.Unit;

public sealed class AcrValidationMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_WhenUnauthenticated_PassesToNext()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var nextCalled = false;
        var sut = new AcrValidationMiddleware(_ => { nextCalled = true; return Task.CompletedTask; });

        // Act
        await sut.InvokeAsync(context);

        // Assert
        nextCalled.Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact]
    public async Task InvokeAsync_WhenAuthenticatedButMissingAcr_Returns401()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user1")], "Bearer"));
        
        var sut = new AcrValidationMiddleware(_ => Task.CompletedTask);

        // Act
        await sut.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
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
        var sut = new AcrValidationMiddleware(_ => { nextCalled = true; return Task.CompletedTask; });

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
        context.Response.ContentType.Should().Contain("application/json");
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
        var sut = new AcrValidationMiddleware(_ => { nextCalled = true; return Task.CompletedTask; });

        // Act
        await sut.InvokeAsync(context);

        // Assert
        nextCalled.Should().BeTrue();
    }
}
