using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Domain.Auth;

namespace Sentinel.Tests.Unit;

public sealed class ForgotPasswordHandlerTests
{
    [Fact]
    public async Task HandleAsync_WhenCaptchaFails_DoesNothing()
    {
        var keycloak = new Mock<IKeycloakAdminService>();
        var tokenProvider = new Mock<IResetTokenProvider>();
        var email = new Mock<IEmailService>();
        var captcha = new Mock<ICaptchaService>();
        captcha.Setup(x => x.VerifyAsync("captcha", It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var sut = new ForgotPasswordHandler(
            keycloak.Object,
            tokenProvider.Object,
            email.Object,
            captcha.Object,
            NullLogger<ForgotPasswordHandler>.Instance);

        await sut.HandleAsync(new ForgotPasswordRequest("user@example.com", "captcha"), CancellationToken.None);

        keycloak.Verify(x => x.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        email.Verify(x => x.SendResetPasswordEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WhenUserExists_SendsResetEmail()
    {
        var keycloak = new Mock<IKeycloakAdminService>();
        keycloak
            .Setup(x => x.GetUserByEmailAsync("user@example.com", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new KeycloakUserSummary("id-1", "user@example.com", "user"));

        var tokenProvider = new Mock<IResetTokenProvider>();
        tokenProvider.Setup(x => x.GenerateToken("user@example.com")).Returns("reset-token");

        var email = new Mock<IEmailService>();
        var captcha = new Mock<ICaptchaService>();
        captcha.Setup(x => x.VerifyAsync("captcha", It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var sut = new ForgotPasswordHandler(
            keycloak.Object,
            tokenProvider.Object,
            email.Object,
            captcha.Object,
            NullLogger<ForgotPasswordHandler>.Instance);

        await sut.HandleAsync(new ForgotPasswordRequest("user@example.com", "captcha"), CancellationToken.None);

        email.Verify(x => x.SendResetPasswordEmailAsync("user@example.com", "reset-token", It.IsAny<CancellationToken>()), Times.Once);
    }
}
