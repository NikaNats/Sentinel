using FluentAssertions;
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

namespace Sentinel.Tests.Security;

public sealed class ForgotPasswordAntiEnumerationSecurityTests
{
    [Fact]
    public async Task ForgotPassword_WhenUserDoesNotExist_Returns202Accepted()
    {
        var keycloak = new Mock<IKeycloakUserService>();
        keycloak.Setup(x => x.GetUserByEmailAsync("missing@example.com", It.IsAny<CancellationToken>()))
            .ReturnsAsync((KeycloakUserSummary?)null);

        var captcha = new Mock<ICaptchaService>();
        captcha.Setup(x => x.VerifyAsync("captcha", It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var handler = new ForgotPasswordHandler(
            keycloak.Object,
            Mock.Of<IResetTokenProvider>(),
            Mock.Of<IEmailService>(),
            captcha.Object,
            NullLogger<ForgotPasswordHandler>.Instance);

        var controller = BuildController(handler);
        var result = await controller.ForgotPassword(new ForgotPasswordRequest("missing@example.com", "captcha"),
            CancellationToken.None);

        result.Should().BeOfType<AcceptedResult>();
    }

    [Fact]
    public async Task ForgotPassword_WhenInputMalformed_StillReturns202Accepted()
    {
        var handler = new ForgotPasswordHandler(
            Mock.Of<IKeycloakUserService>(),
            Mock.Of<IResetTokenProvider>(),
            Mock.Of<IEmailService>(),
            Mock.Of<ICaptchaService>(),
            NullLogger<ForgotPasswordHandler>.Instance);

        var controller = BuildController(handler);
        var result = await controller.ForgotPassword(new ForgotPasswordRequest(" ", " "), CancellationToken.None);

        result.Should().BeOfType<AcceptedResult>();
    }

    [Fact]
    public async Task ForgotPassword_WhenInternalErrorOccurs_StillReturns202Accepted()
    {
        var keycloak = new Mock<IKeycloakUserService>();
        keycloak.Setup(x => x.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("upstream error"));

        var captcha = new Mock<ICaptchaService>();
        captcha.Setup(x => x.VerifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var handler = new ForgotPasswordHandler(
            keycloak.Object,
            Mock.Of<IResetTokenProvider>(),
            Mock.Of<IEmailService>(),
            captcha.Object,
            NullLogger<ForgotPasswordHandler>.Instance);

        var controller = BuildController(handler);
        var result = await controller.ForgotPassword(new ForgotPasswordRequest("user@example.com", "captcha"),
            CancellationToken.None);

        result.Should().BeOfType<AcceptedResult>();
    }

    private static UsersController BuildController(ForgotPasswordHandler forgotHandler)
    {
        var registerHandler = new RegisterUserHandler(
            Mock.Of<ICaptchaService>(),
            Mock.Of<IKeycloakUserService>(),
            Mock.Of<IEmailService>(),
            Mock.Of<IEmailVerificationTokenStore>(),
            Mock.Of<IPasswordStrengthValidator>());

        var resendHandler = new ResendVerificationHandler(
            Mock.Of<IKeycloakUserService>(),
            Mock.Of<IEmailVerificationTokenStore>(),
            Mock.Of<IEmailService>(),
            NullLogger<ResendVerificationHandler>.Instance);

        var resetHandler = new ResetPasswordHandler(
            Mock.Of<IResetTokenProvider>(),
            Mock.Of<IKeycloakUserService>(),
            Mock.Of<IKeycloakProfileService>(),
            Mock.Of<IJtiReplayCache>(),
            Mock.Of<IAuthRevocationService>());

        return new UsersController(
            registerHandler,
            forgotHandler,
            resetHandler,
            resendHandler,
            Mock.Of<IEmailVerificationTokenStore>(),
            Mock.Of<IKeycloakUserService>())
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };
    }
}
