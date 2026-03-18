using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Controllers;

namespace Sentinel.Tests.Unit;

public sealed class UsersControllerTests
{
    [Fact]
    public async Task Register_WhenHandlerReturnsError_ReturnsBadRequest()
    {
        var captcha = new Mock<ICaptchaService>();
        captcha.Setup(x => x.VerifyAsync("bad-captcha", It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var handler = new RegisterUserHandler(
            captcha.Object,
            Mock.Of<IKeycloakAdminService>(),
            Mock.Of<IEmailService>(),
            Mock.Of<IEmailVerificationTokenStore>());
        var verificationStore = new Mock<IEmailVerificationTokenStore>();
        var keycloakAdmin = new Mock<IKeycloakAdminService>();

        var controller = new UsersController(handler, verificationStore.Object, keycloakAdmin.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };

        var response = await controller.Register(
            new RegisterUserRequest("user@example.com", "user", "Passw0rd!", "bad-captcha", true),
            CancellationToken.None);

        var badRequest = Assert.IsType<BadRequestObjectResult>(response);
        Assert.Equal(StatusCodes.Status400BadRequest, badRequest.StatusCode);
    }

    [Fact]
    public async Task VerifyEmail_WhenTokenUnknown_ReturnsBadRequest()
    {
        var handler = new RegisterUserHandler(
            Mock.Of<ICaptchaService>(),
            Mock.Of<IKeycloakAdminService>(),
            Mock.Of<IEmailService>(),
            Mock.Of<IEmailVerificationTokenStore>());

        var controller = new UsersController(
            handler,
            BuildVerificationStore(null),
            Mock.Of<IKeycloakAdminService>());

        var response = await controller.VerifyEmail("missing-token", CancellationToken.None);

        var badRequest = Assert.IsType<BadRequestObjectResult>(response);
        Assert.Equal(StatusCodes.Status400BadRequest, badRequest.StatusCode);
    }

    [Fact]
    public async Task VerifyEmail_WhenTokenValid_MarksEmailVerified()
    {
        var keycloakAdmin = new Mock<IKeycloakAdminService>();
        keycloakAdmin
            .Setup(x => x.SetEmailVerifiedAsync("kc-user-1", true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var handler = new RegisterUserHandler(
            Mock.Of<ICaptchaService>(),
            keycloakAdmin.Object,
            Mock.Of<IEmailService>(),
            Mock.Of<IEmailVerificationTokenStore>());

        var controller = new UsersController(
            handler,
            BuildVerificationStore("kc-user-1"),
            keycloakAdmin.Object);

        var response = await controller.VerifyEmail("token-1", CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(response);
        Assert.Equal(StatusCodes.Status200OK, ok.StatusCode);
        keycloakAdmin.Verify(x => x.SetEmailVerifiedAsync("kc-user-1", true, It.IsAny<CancellationToken>()), Times.Once);
    }

    private static IEmailVerificationTokenStore BuildVerificationStore(string? userId)
    {
        var store = new Mock<IEmailVerificationTokenStore>();
        store
            .Setup(x => x.ConsumeAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(userId);
        return store.Object;
    }
}
