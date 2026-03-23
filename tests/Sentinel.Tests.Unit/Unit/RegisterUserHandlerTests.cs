using Moq;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Domain.Users;
using Sentinel.Security.Abstractions.Identity;
using Sentinel.Security.Abstractions.Results;

namespace Sentinel.Tests.Unit;

public sealed class RegisterUserHandlerTests
{
    [Fact]
    public async Task HandleAsync_WhenCaptchaInvalid_ReturnsBadRequestResult()
    {
        var captcha = new Mock<ICaptchaService>();
        var identityRegistry = new Mock<IIdentityRegistry>();
        var email = new Mock<IEmailService>();
        var tokenStore = new Mock<IEmailVerificationTokenStore>();

        captcha
            .Setup(x => x.VerifyAsync("captcha-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var validator = new Mock<IPasswordStrengthValidator>();
        validator.Setup(x => x.Validate(It.IsAny<string>())).Returns(new PasswordStrengthValidationResult(true));

        var sut = new RegisterUserHandler(captcha.Object, identityRegistry.Object, email.Object, tokenStore.Object,
            validator.Object);

        var result = await sut.HandleAsync(
            new RegisterUserRequest("user@example.com", "user", "Passw0rd!", "captcha-token", true),
            "ip-hash",
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal("Invalid captcha.", result.ErrorMessage);
        identityRegistry.Verify(
            x => x.CreateUserAsync(It.IsAny<IdentityRegistration>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WhenTermsNotAccepted_ReturnsValidationError()
    {
        var sut = new RegisterUserHandler(
            Mock.Of<ICaptchaService>(),
            Mock.Of<IIdentityRegistry>(),
            Mock.Of<IEmailService>(),
            Mock.Of<IEmailVerificationTokenStore>(),
            Mock.Of<IPasswordStrengthValidator>());

        var result = await sut.HandleAsync(
            new RegisterUserRequest("user@example.com", "user", "Passw0rd!", "captcha-token", false),
            "ip-hash",
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal("Terms must be accepted.", result.ErrorMessage);
    }

    [Fact]
    public async Task HandleAsync_WhenValidRequest_CreatesUserStoresTokenAndSendsEmail()
    {
        var captcha = new Mock<ICaptchaService>();
        var identityRegistry = new Mock<IIdentityRegistry>();
        var email = new Mock<IEmailService>();
        var tokenStore = new Mock<IEmailVerificationTokenStore>();

        captcha
            .Setup(x => x.VerifyAsync("captcha-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        identityRegistry
            .Setup(x => x.CreateUserAsync(It.IsAny<IdentityRegistration>(), "Passw0rd!", It.IsAny<CancellationToken>()))
            .ReturnsAsync("kc-user-1");
        tokenStore
            .Setup(x => x.StoreAsync(It.IsAny<string>(), "kc-user-1", TimeSpan.FromHours(24),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var validator = new Mock<IPasswordStrengthValidator>();
        validator.Setup(x => x.Validate("Passw0rd!")).Returns(new PasswordStrengthValidationResult(true));

        var sut = new RegisterUserHandler(captcha.Object, identityRegistry.Object, email.Object, tokenStore.Object,
            validator.Object);

        var result = await sut.HandleAsync(
            new RegisterUserRequest("user@example.com", "user", "Passw0rd!", "captcha-token", true),
            "ip-hash",
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        email.Verify(
            x => x.SendVerificationEmailAsync("user@example.com", It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task HandleAsync_WhenPasswordIsWeak_ReturnsWeakPassword()
    {
        var captcha = new Mock<ICaptchaService>();
        captcha
            .Setup(x => x.VerifyAsync("captcha-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var validator = new Mock<IPasswordStrengthValidator>();
        validator
            .Setup(x => x.Validate("weak"))
            .Returns(new PasswordStrengthValidationResult(false, "weak_password", "Password is too weak."));

        var sut = new RegisterUserHandler(
            captcha.Object,
            Mock.Of<IIdentityRegistry>(),
            Mock.Of<IEmailService>(),
            Mock.Of<IEmailVerificationTokenStore>(),
            validator.Object);

        var result = await sut.HandleAsync(
            new RegisterUserRequest("user@example.com", "user", "weak", "captcha-token", true),
            "ip-hash",
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal("Password is too weak.", result.ErrorMessage);
    }

    [Fact]
    public async Task HandleAsync_WhenUserAlreadyExists_ReturnsGenericSuccessMessage()
    {
        var captcha = new Mock<ICaptchaService>();
        var identityRegistry = new Mock<IIdentityRegistry>();
        var email = new Mock<IEmailService>();
        var tokenStore = new Mock<IEmailVerificationTokenStore>();
        var validator = new Mock<IPasswordStrengthValidator>();

        captcha
            .Setup(x => x.VerifyAsync("captcha-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        validator
            .Setup(x => x.Validate("StrongPassw0rd!"))
            .Returns(new PasswordStrengthValidationResult(true));
        identityRegistry
            .Setup(x => x.CreateUserAsync(It.IsAny<IdentityRegistration>(), "StrongPassw0rd!",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(SecurityResult<string>.Failure(SecurityErrors.IdentityConflictMessage));

        var sut = new RegisterUserHandler(captcha.Object, identityRegistry.Object, email.Object, tokenStore.Object,
            validator.Object);

        var result = await sut.HandleAsync(
            new RegisterUserRequest("user@example.com", "user", "StrongPassw0rd!", "captcha-token", true),
            "ip-hash",
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("If this email is new, you'll receive a verification email.", result.Value.Message);
        email.Verify(x => x.SendWelcomeOrAlreadyRegisteredEmailAsync("user@example.com", It.IsAny<CancellationToken>()),
            Times.Once);
        tokenStore.Verify(
            x => x.StoreAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan>(),
                It.IsAny<CancellationToken>()), Times.Never);
    }
}
