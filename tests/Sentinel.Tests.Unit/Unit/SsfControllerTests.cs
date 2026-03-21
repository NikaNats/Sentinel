using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Controllers;
using Sentinel.Infrastructure.Auth.Ssf;

namespace Sentinel.Tests.Unit;

public sealed class SsfControllerTests
{
    [Fact]
    public async Task ReceiveEvent_WhenAuthTokenMissing_ReturnsUnauthorized()
    {
        var processor = new Mock<ISsfEventProcessor>();
        var sut = CreateController(
            processor.Object,
            new SsfOptions { Enabled = true, RequireAuthToken = true, AuthToken = "expected-token" });
        sut.ControllerContext.HttpContext.Request.Body = BuildJsonSetBody("set-token");

        var result = await sut.ReceiveEvent(CancellationToken.None);

        var unauthorized = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, unauthorized.StatusCode);
        processor.Verify(x => x.ProcessAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ReceiveEvent_WhenAuthTokenInvalid_ReturnsUnauthorized()
    {
        var processor = new Mock<ISsfEventProcessor>();
        var sut = CreateController(
            processor.Object,
            new SsfOptions { Enabled = true, RequireAuthToken = true, AuthToken = "expected-token" });
        sut.ControllerContext.HttpContext.Request.Headers["SSF-Auth-Token"] = "expected-token-x";
        sut.ControllerContext.HttpContext.Request.Body = BuildJsonSetBody("set-token");

        var result = await sut.ReceiveEvent(CancellationToken.None);

        var unauthorized = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, unauthorized.StatusCode);
        processor.Verify(x => x.ProcessAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ReceiveEvent_WhenAuthTokenValid_ProcessesSet()
    {
        var processor = new Mock<ISsfEventProcessor>();
        processor.Setup(x => x.ProcessAsync("set-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(SsfProcessResult.Success());

        var sut = CreateController(
            processor.Object,
            new SsfOptions { Enabled = true, RequireAuthToken = true, AuthToken = "expected-token" });
        sut.ControllerContext.HttpContext.Request.Headers["SSF-Auth-Token"] = "expected-token";
        sut.ControllerContext.HttpContext.Request.Body = BuildJsonSetBody("set-token");

        var result = await sut.ReceiveEvent(CancellationToken.None);

        Assert.IsType<AcceptedResult>(result);
        processor.Verify(x => x.ProcessAsync("set-token", It.IsAny<CancellationToken>()), Times.Once);
    }

    private static SsfController CreateController(ISsfEventProcessor processor, SsfOptions options)
    {
        var controller = new SsfController(
            processor,
            Options.Create(options),
            NullLogger<SsfController>.Instance)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };

        controller.ControllerContext.HttpContext.Request.ContentType = "application/json";
        return controller;
    }

    private static MemoryStream BuildJsonSetBody(string setToken)
    {
        return new MemoryStream(Encoding.UTF8.GetBytes($$"""{"set":"{{setToken}}"}"""));
    }
}
