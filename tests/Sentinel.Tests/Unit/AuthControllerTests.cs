using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Controllers;
using System.Security.Claims;

namespace Sentinel.Tests.Unit;

public sealed class AuthControllerTests
{
    [Fact]
    public async Task Refresh_WhenReuseDetected_ReturnsTokenTheftProblemDetails()
    {
        var refreshService = new Mock<ITokenRefreshService>();
        var revocationService = new Mock<IAuthRevocationService>();
        var blacklistCache = new Mock<ISessionBlacklistCache>();
        refreshService
            .Setup(x => x.RefreshTokenAsync("old-refresh", "proof", It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TokenRefreshResult(false, null, null, true));

        var controller = new AuthController(refreshService.Object, revocationService.Object, blacklistCache.Object)
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
        var revocationService = new Mock<IAuthRevocationService>();
        var blacklistCache = new Mock<ISessionBlacklistCache>();
        var controller = new AuthController(refreshService.Object, revocationService.Object, blacklistCache.Object);

        var result = await controller.Refresh(new AuthController.RefreshRequest(string.Empty), CancellationToken.None);

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal(StatusCodes.Status400BadRequest, badRequest.StatusCode);
    }

    [Fact]
    public async Task Logout_WhenAuthorized_BlacklistsSidAndRevokesCurrentSession()
    {
        var refreshService = new Mock<ITokenRefreshService>();
        var revocationService = new Mock<IAuthRevocationService>();
        var blacklistCache = new Mock<ISessionBlacklistCache>();

        revocationService
            .Setup(x => x.RevokeCurrentSessionAsync("refresh-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var controller = new AuthController(refreshService.Object, revocationService.Object, blacklistCache.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(new ClaimsIdentity(
                    [
                        new Claim("sid", "sid-1"),
                        new Claim("sub", "user-1")
                    ], "test"))
                }
            }
        };

        var result = await controller.Logout(new AuthController.RevokeRequest("refresh-token"), CancellationToken.None);

        Assert.IsType<NoContentResult>(result);
        blacklistCache.Verify(x => x.BlacklistSessionAsync("sid-1", TimeSpan.FromMinutes(5), It.IsAny<CancellationToken>()), Times.Once);
        revocationService.Verify(x => x.RevokeCurrentSessionAsync("refresh-token", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task GlobalLogout_WhenRevocationFails_Returns500()
    {
        var refreshService = new Mock<ITokenRefreshService>();
        var revocationService = new Mock<IAuthRevocationService>();
        var blacklistCache = new Mock<ISessionBlacklistCache>();

        revocationService
            .Setup(x => x.RevokeAllSessionsAsync("user-1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var controller = new AuthController(refreshService.Object, revocationService.Object, blacklistCache.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(new ClaimsIdentity(
                    [
                        new Claim("sid", "sid-1"),
                        new Claim("sub", "user-1")
                    ], "test"))
                }
            }
        };

        var result = await controller.GlobalLogout(CancellationToken.None);

        var objectResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status500InternalServerError, objectResult.StatusCode);
    }
}
