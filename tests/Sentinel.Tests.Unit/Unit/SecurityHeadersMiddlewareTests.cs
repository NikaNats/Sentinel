using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Moq;
using Sentinel.Middleware;

namespace Sentinel.Tests.Unit;

public sealed class SecurityHeadersMiddlewareTests
{
    [Theory]
    [InlineData(StatusCodes.Status200OK)]
    [InlineData(StatusCodes.Status401Unauthorized)]
    [InlineData(StatusCodes.Status403Forbidden)]
    [InlineData(StatusCodes.Status500InternalServerError)]
    public async Task InvokeAsync_AddsSecurityHeaders_AndRemovesServerFingerprintHeaders(int statusCode)
    {
        var context = new DefaultHttpContext();
        context.Response.Headers.Append("Server", "Kestrel");
        context.Response.Headers.Append("X-Powered-By", "AspNetCore");

        RequestDelegate next = _ =>
        {
            context.Response.StatusCode = statusCode;
            return Task.CompletedTask;
        };

        // Mock production environment (not development)
        var envMock = new Mock<IWebHostEnvironment>();
        envMock.SetupGet(e => e.EnvironmentName).Returns("Production");

        var middleware = new SecurityHeadersMiddleware(next, envMock.Object);

        await middleware.InvokeAsync(context);

        Assert.Equal("max-age=63072000; includeSubDomains; preload",
            context.Response.Headers["Strict-Transport-Security"].ToString());
        Assert.Equal("default-src 'none'; frame-ancestors 'none'",
            context.Response.Headers["Content-Security-Policy"].ToString());
        Assert.Equal("nosniff", context.Response.Headers["X-Content-Type-Options"].ToString());
        Assert.Equal("DENY", context.Response.Headers["X-Frame-Options"].ToString());
        Assert.Equal("no-referrer", context.Response.Headers["Referrer-Policy"].ToString());
        Assert.Equal("geolocation=(), microphone=(), camera=()",
            context.Response.Headers["Permissions-Policy"].ToString());
        Assert.Equal("no-store", context.Response.Headers["Cache-Control"].ToString());
        Assert.Equal("no-cache", context.Response.Headers["Pragma"].ToString());
        Assert.False(context.Response.Headers.ContainsKey("Server"));
        Assert.False(context.Response.Headers.ContainsKey("X-Powered-By"));
    }
}
