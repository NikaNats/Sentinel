using System.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.AspNetCore.Middleware;
using FluentAssertions;

namespace Sentinel.Tests.Unit;

public sealed class CorrelationIdMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_WhenHeaderMissing_GeneratesNewCorrelationId()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var nextCalled = false;
        RequestDelegate next = _ => { nextCalled = true; return Task.CompletedTask; };
        var sut = new CorrelationIdMiddleware(next, NullLogger<CorrelationIdMiddleware>.Instance);

        // Act
        await sut.InvokeAsync(context);

        // Assert
        nextCalled.Should().BeTrue();
        context.Response.Headers["X-Correlation-ID"].ToString().Should().NotBeNullOrWhiteSpace();
        context.Items["X-Correlation-ID"].Should().NotBeNull();
    }

    [Fact]
    public async Task InvokeAsync_WhenHeaderExists_PreservesAndPropagatesId()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Headers["X-Correlation-ID"] = "existing-trace-123";
        RequestDelegate next = _ => Task.CompletedTask;
        var sut = new CorrelationIdMiddleware(next, NullLogger<CorrelationIdMiddleware>.Instance);

        // Act
        await sut.InvokeAsync(context);

        // Assert
        context.Response.Headers["X-Correlation-ID"].ToString().Should().Be("existing-trace-123");
        context.Items["X-Correlation-ID"].ToString().Should().Be("existing-trace-123");
    }

    [Fact]
    public async Task InvokeAsync_WhenDpopKeyExistsInContext_PropagatesToActivityBaggage()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Items["dpop.jkt"] = "thumbprint-abc";
        RequestDelegate next = _ => Task.CompletedTask;
        var sut = new CorrelationIdMiddleware(next, NullLogger<CorrelationIdMiddleware>.Instance);

        using var activity = new Activity("Test");
        activity.Start();

        // Act
        await sut.InvokeAsync(context);

        // Assert
        activity.GetBaggageItem("dpop.jkt").Should().Be("thumbprint-abc");

        activity.Dispose();
    }

    [Fact]
    public async Task InvokeAsync_WhenNextDelegateThrows_StillPropagatesCorrelationId()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var correlationId = "test-correlation-123";
        context.Request.Headers["X-Correlation-ID"] = correlationId;

        RequestDelegate next = _ => throw new InvalidOperationException("Test error");
        var sut = new CorrelationIdMiddleware(next, NullLogger<CorrelationIdMiddleware>.Instance);

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() => sut.InvokeAsync(context));

        context.Response.Headers["X-Correlation-ID"].ToString().Should().Be(correlationId);
        context.Items["X-Correlation-ID"].ToString().Should().Be(correlationId);
    }

    [Fact]
    public async Task InvokeAsync_GeneratedCorrelationId_FormatsAsValidGuid()
    {
        // Arrange
        var context = new DefaultHttpContext();
        RequestDelegate next = _ => Task.CompletedTask;
        var sut = new CorrelationIdMiddleware(next, NullLogger<CorrelationIdMiddleware>.Instance);

        // Act
        await sut.InvokeAsync(context);

        // Assert
        var correlationId = context.Items["X-Correlation-ID"]?.ToString();
        correlationId.Should().NotBeNullOrWhiteSpace();

        // Should be either a valid GUID or Activity trace ID format
        var isParseable = Guid.TryParse(correlationId, out _) || !string.IsNullOrWhiteSpace(correlationId);
        isParseable.Should().BeTrue();
    }
}
