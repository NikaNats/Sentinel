using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Controllers;
using Sentinel.Domain.Auth;
using Sentinel.Presentation.Controllers;
using Sentinel.Security.Abstractions.Identity;

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
            Mock.Of<IKeycloakUserService>(),
            Mock.Of<IEmailService>(),
            Mock.Of<IEmailVerificationTokenStore>(),
            BuildPasswordStrengthValidator());
        var verificationStore = new Mock<IEmailVerificationTokenStore>();
        var keycloakUser = new Mock<IKeycloakUserService>();

        var controller = new UsersController(
            handler,
            BuildForgotPasswordHandler(),
            BuildResetPasswordHandler(),
            BuildResendVerificationHandler(),
            verificationStore.Object,
            keycloakUser.Object)
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
            Mock.Of<IKeycloakUserService>(),
            Mock.Of<IEmailService>(),
            Mock.Of<IEmailVerificationTokenStore>(),
            BuildPasswordStrengthValidator());

        var controller = new UsersController(
            handler,
            BuildForgotPasswordHandler(),
            BuildResetPasswordHandler(),
            BuildResendVerificationHandler(),
            BuildVerificationStore(null),
            Mock.Of<IKeycloakUserService>());

        var response = await controller.VerifyEmail("missing-token", CancellationToken.None);

        var badRequest = Assert.IsType<BadRequestObjectResult>(response);
        Assert.Equal(StatusCodes.Status400BadRequest, badRequest.StatusCode);
    }

    [Fact]
    public async Task VerifyEmail_WhenTokenValid_MarksEmailVerified()
    {
        var keycloakUser = new Mock<IKeycloakUserService>();
        keycloakUser
            .Setup(x => x.SetEmailVerifiedAsync("kc-user-1", true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var handler = new RegisterUserHandler(
            Mock.Of<ICaptchaService>(),
            keycloakUser.Object,
            Mock.Of<IEmailService>(),
            Mock.Of<IEmailVerificationTokenStore>(),
            BuildPasswordStrengthValidator());

        var controller = new UsersController(
            handler,
            BuildForgotPasswordHandler(),
            BuildResetPasswordHandler(),
            BuildResendVerificationHandler(),
            BuildVerificationStore("kc-user-1"),
            keycloakUser.Object);

        var response = await controller.VerifyEmail("token-1", CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(response);
        Assert.Equal(StatusCodes.Status200OK, ok.StatusCode);
        keycloakUser.Verify(x => x.SetEmailVerifiedAsync("kc-user-1", true, It.IsAny<CancellationToken>()), Times.Once);
    }

    private static IEmailVerificationTokenStore BuildVerificationStore(string? userId)
    {
        var store = new Mock<IEmailVerificationTokenStore>();
        store
            .Setup(x => x.ConsumeAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(userId);
        return store.Object;
    }

    [Fact]
    public async Task ForgotPassword_AlwaysReturnsAccepted()
    {
        var controller = new UsersController(
            BuildRegisterUserHandler(),
            BuildForgotPasswordHandler(),
            BuildResetPasswordHandler(),
            BuildResendVerificationHandler(),
            BuildVerificationStore(null),
            Mock.Of<IKeycloakUserService>());

        var response = await controller.ForgotPassword(new ForgotPasswordRequest("unknown@example.com", "captcha"),
            CancellationToken.None);

        Assert.IsType<AcceptedResult>(response);
    }

    private static RegisterUserHandler BuildRegisterUserHandler()
    {
        return new RegisterUserHandler(
            Mock.Of<ICaptchaService>(),
            Mock.Of<IKeycloakUserService>(),
            Mock.Of<IEmailService>(),
            Mock.Of<IEmailVerificationTokenStore>(),
            BuildPasswordStrengthValidator());
    }

    private static IPasswordStrengthValidator BuildPasswordStrengthValidator()
    {
        var validator = new Mock<IPasswordStrengthValidator>();
        validator.Setup(x => x.Validate(It.IsAny<string>())).Returns(new PasswordStrengthValidationResult(true));
        return validator.Object;
    }

    private static ResendVerificationHandler BuildResendVerificationHandler()
    {
        return new ResendVerificationHandler(
            Mock.Of<IIdentityProvider>(),
            Mock.Of<IEmailVerificationTokenStore>(),
            Mock.Of<IEmailService>(),
            NullLogger<ResendVerificationHandler>.Instance);
    }

    private static ForgotPasswordHandler BuildForgotPasswordHandler()
    {
        return new ForgotPasswordHandler(
            Mock.Of<IIdentityProvider>(),
            Mock.Of<IResetTokenProvider>(),
            Mock.Of<IEmailService>(),
            Mock.Of<ICaptchaService>(),
            NullLogger<ForgotPasswordHandler>.Instance);
    }

    private static ResetPasswordHandler BuildResetPasswordHandler()
    {
        return new ResetPasswordHandler(
            Mock.Of<IResetTokenProvider>(),
            Mock.Of<IIdentityProvider>(),
            Mock.Of<IJtiReplayCache>(),
            Mock.Of<IAuthRevocationService>());
    }
}
