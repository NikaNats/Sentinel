using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Controllers;

namespace Sentinel.Tests.Unit;

public sealed class TokenExchangeControllerTests
{
    [Fact]
    public async Task ExchangeExternalToken_WhenDpopMissing_ReturnsBadRequest()
    {
        var service = new Mock<ITokenExchangeService>();
        var controller = new TokenExchangeController(service.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };

        var response = await controller.ExchangeExternalToken(new TokenExchangeController.TokenExchangeRequest("token", "google", "pkce-verifier"), CancellationToken.None);

        var badRequest = Assert.IsType<BadRequestObjectResult>(response);
        Assert.Equal(StatusCodes.Status400BadRequest, badRequest.StatusCode);
    }

    [Fact]
    public async Task ExchangeExternalToken_WhenServiceSucceeds_ReturnsOk()
    {
        var service = new Mock<ITokenExchangeService>();
        service
            .Setup(x => x.ExchangeExternalTokenAsync("token", "google", "proof", "pkce-verifier", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TokenExchangeResult
            {
                AccessToken = "sentinel-access",
                RefreshToken = "sentinel-refresh",
                TokenType = "DPoP",
                ExpiresIn = 300
            });

        var controller = new TokenExchangeController(service.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };
        controller.Request.Headers["DPoP"] = "proof";

        var response = await controller.ExchangeExternalToken(new TokenExchangeController.TokenExchangeRequest("token", "google", "pkce-verifier"), CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(response);
        Assert.Equal(StatusCodes.Status200OK, ok.StatusCode);
    }
}
