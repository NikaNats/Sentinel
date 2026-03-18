using Moq;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Domain.Users;

namespace Sentinel.Tests.Unit;

public sealed class RegisterUserHandlerTests
{
    [Fact]
    public async Task HandleAsync_WhenCaptchaInvalid_ReturnsBadRequestResult()
    {
        var captcha = new Mock<ICaptchaService>();
        var keycloak = new Mock<IKeycloakAdminService>();
        var email = new Mock<IEmailService>();
        var tokenStore = new Mock<IEmailVerificationTokenStore>();

        captcha
            .Setup(x => x.VerifyAsync("captcha-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var sut = new RegisterUserHandler(captcha.Object, keycloak.Object, email.Object, tokenStore.Object);

        var result = await sut.HandleAsync(
            new RegisterUserRequest("user@example.com", "user", "Passw0rd!", "captcha-token", true),
            "ip-hash",
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal("invalid_captcha", result.ErrorCode);
        keycloak.Verify(x => x.CreateUserAsync(It.IsAny<UserRegistration>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WhenTermsNotAccepted_ReturnsValidationError()
    {
        var sut = new RegisterUserHandler(
            Mock.Of<ICaptchaService>(),
            Mock.Of<IKeycloakAdminService>(),
            Mock.Of<IEmailService>(),
            Mock.Of<IEmailVerificationTokenStore>());

        var result = await sut.HandleAsync(
            new RegisterUserRequest("user@example.com", "user", "Passw0rd!", "captcha-token", false),
            "ip-hash",
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal("terms_not_accepted", result.ErrorCode);
    }

    [Fact]
    public async Task HandleAsync_WhenValidRequest_CreatesUserStoresTokenAndSendsEmail()
    {
        var captcha = new Mock<ICaptchaService>();
        var keycloak = new Mock<IKeycloakAdminService>();
        var email = new Mock<IEmailService>();
        var tokenStore = new Mock<IEmailVerificationTokenStore>();

        captcha
            .Setup(x => x.VerifyAsync("captcha-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        keycloak
            .Setup(x => x.CreateUserAsync(It.IsAny<UserRegistration>(), "Passw0rd!", It.IsAny<CancellationToken>()))
            .ReturnsAsync("kc-user-1");
        tokenStore
            .Setup(x => x.StoreAsync(It.IsAny<string>(), "kc-user-1", TimeSpan.FromHours(24), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var sut = new RegisterUserHandler(captcha.Object, keycloak.Object, email.Object, tokenStore.Object);

        var result = await sut.HandleAsync(
            new RegisterUserRequest("user@example.com", "user", "Passw0rd!", "captcha-token", true),
            "ip-hash",
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        email.Verify(x => x.SendVerificationEmailAsync("user@example.com", It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }
}
