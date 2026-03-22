using Moq;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Domain.Auth;
using Sentinel.Security.Abstractions.Identity;

namespace Sentinel.Tests.Unit;

public sealed class ResetPasswordHandlerTests
{
    [Fact]
    public async Task HandleAsync_WhenTokenInvalid_ReturnsBadRequestResult()
    {
        var resetTokenProvider = new Mock<IResetTokenProvider>();
        resetTokenProvider.Setup(x => x.ValidateToken("bad-token")).Returns((false, null));

        var sut = new ResetPasswordHandler(
            resetTokenProvider.Object,
            Mock.Of<IIdentityProvider>(),
            Mock.Of<IJtiReplayCache>(),
            Mock.Of<IAuthRevocationService>());

        var result =
            await sut.HandleAsync(new ResetPasswordRequest("bad-token", "NewPassw0rd!"), CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal("invalid_or_expired_token", result.ErrorCode);
    }

    [Fact]
    public async Task HandleAsync_WhenTokenAlreadyConsumed_ReturnsError()
    {
        var resetTokenProvider = new Mock<IResetTokenProvider>();
        resetTokenProvider.Setup(x => x.ValidateToken("token")).Returns((true, "user@example.com"));

        var replay = new Mock<IJtiReplayCache>();
        replay.Setup(x =>
                x.TryStoreIfNotExistsAsync(It.IsAny<string>(), TimeSpan.FromMinutes(15), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var sut = new ResetPasswordHandler(
            resetTokenProvider.Object,
            Mock.Of<IIdentityProvider>(),
            replay.Object,
            Mock.Of<IAuthRevocationService>());

        var result = await sut.HandleAsync(new ResetPasswordRequest("token", "NewPassw0rd!"), CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal("token_already_consumed", result.ErrorCode);
    }

    [Fact]
    public async Task HandleAsync_WhenEverythingValid_ReturnsSuccess()
    {
        var resetTokenProvider = new Mock<IResetTokenProvider>();
        resetTokenProvider.Setup(x => x.ValidateToken("token")).Returns((true, "user@example.com"));

        var identityProvider = new Mock<IIdentityProvider>();
        identityProvider
            .Setup(x => x.UpdatePasswordAsync("user@example.com", "NewPassw0rd!", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        identityProvider.Setup(x => x.GetUserByEmailAsync("user@example.com", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new IdentityUserSummary { Id = "id-1", Email = "user@example.com", Username = "user" });

        var replay = new Mock<IJtiReplayCache>();
        replay.Setup(x =>
                x.TryStoreIfNotExistsAsync(It.IsAny<string>(), TimeSpan.FromMinutes(15), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var revocation = new Mock<IAuthRevocationService>();
        revocation.Setup(x => x.RevokeAllSessionsAsync("id-1", It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var sut = new ResetPasswordHandler(
            resetTokenProvider.Object,
            identityProvider.Object,
            replay.Object,
            revocation.Object);

        var result = await sut.HandleAsync(new ResetPasswordRequest("token", "NewPassw0rd!"), CancellationToken.None);

        Assert.True(result.IsSuccess);
    }
}
