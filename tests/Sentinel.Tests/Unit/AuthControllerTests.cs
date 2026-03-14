using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Controllers;

namespace Sentinel.Tests.Unit;

public sealed class AuthControllerTests
{
    [Fact]
    public async Task Refresh_WhenReuseDetected_ReturnsTokenTheftProblemDetails()
    {
        var refreshService = new Mock<ITokenRefreshService>();
        refreshService
            .Setup(x => x.RefreshTokenAsync("old-refresh", "proof", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TokenRefreshResult(false, null, null, true));

        var controller = new AuthController(refreshService.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };
        controller.Request.Headers["DPoP"] = "proof";

        var result = await controller.Refresh(new AuthController.RefreshRequest("old-refresh"), CancellationToken.None);

        var unauthorized = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, unauthorized.StatusCode);

        var details = Assert.IsType<ProblemDetails>(unauthorized.Value);
        Assert.Equal("/errors/token-theft-detected", details.Type);
    }

    [Fact]
    public async Task Refresh_WhenRefreshTokenMissing_ReturnsBadRequest()
    {
        var refreshService = new Mock<ITokenRefreshService>();
        var controller = new AuthController(refreshService.Object);

        var result = await controller.Refresh(new AuthController.RefreshRequest(string.Empty), CancellationToken.None);

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal(StatusCodes.Status400BadRequest, badRequest.StatusCode);
    }
}
