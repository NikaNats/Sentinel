using System.Collections.Concurrent;
using FluentAssertions;
using Moq;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Domain.Auth;
using Sentinel.Security.Abstractions.Identity;

namespace Sentinel.Tests.Security;

public sealed class ResetPasswordReplaySecurityTests
{
    [Fact]
    public async Task HandleAsync_WhenTwoRequestsUseSameTokenConcurrently_OnlyOneSucceeds()
    {
        var tokenProvider = new Mock<IResetTokenProvider>();
        tokenProvider.Setup(x => x.ValidateToken("same-token")).Returns((true, "user@example.com"));

        var firstUseState = 0;
        var replayCache = new Mock<IJtiReplayCache>();
        replayCache
            .Setup(x => x.TryStoreIfNotExistsAsync(It.IsAny<string>(), TimeSpan.FromMinutes(15),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => Interlocked.Increment(ref firstUseState) == 1);

        var identityProvider = new Mock<IIdentityProvider>();
        identityProvider
            .Setup(x => x.UpdatePasswordAsync("user@example.com", "N3w!Pass", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        identityProvider
            .Setup(x => x.GetUserByEmailAsync("user@example.com", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new IdentityUserSummary { Id = "kc-user-1", Email = "user@example.com", Username = "user" });

        var revocation = new Mock<IAuthRevocationService>();
        revocation
            .Setup(x => x.RevokeAllSessionsAsync("kc-user-1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var sut = new ResetPasswordHandler(tokenProvider.Object, identityProvider.Object,
            replayCache.Object, revocation.Object);
        var request = new ResetPasswordRequest("same-token", "N3w!Pass");

        var results = new ConcurrentBag<ResetPasswordResult>();
        var cancellationToken = TestContext.Current.CancellationToken;
        await Task.WhenAll(
            Task.Run(async () => results.Add(await sut.HandleAsync(request, cancellationToken)), cancellationToken),
            Task.Run(async () => results.Add(await sut.HandleAsync(request, cancellationToken)), cancellationToken));

        results.Should().HaveCount(2);
        results.Count(x => x.IsSuccess).Should().Be(1);
        results.Count(x => x.ErrorCode == "token_already_consumed").Should().Be(1);
    }

    [Fact]
    public async Task HandleAsync_WhenRequestContainsMalformedInputs_ReturnsInvalidRequest()
    {
        var sut = new ResetPasswordHandler(
            Mock.Of<IResetTokenProvider>(),
            Mock.Of<IIdentityProvider>(),
            Mock.Of<IJtiReplayCache>(),
            Mock.Of<IAuthRevocationService>());

        var result = await sut.HandleAsync(new ResetPasswordRequest("", ""), CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_request");
    }

    [Fact]
    public async Task HandleAsync_WhenTokenIsExpiredOrInvalid_ReturnsInvalidOrExpired()
    {
        var tokenProvider = new Mock<IResetTokenProvider>();
        tokenProvider.Setup(x => x.ValidateToken("expired-token")).Returns((false, null));

        var sut = new ResetPasswordHandler(
            tokenProvider.Object,
            Mock.Of<IIdentityProvider>(),
            Mock.Of<IJtiReplayCache>(),
            Mock.Of<IAuthRevocationService>());

        var result =
            await sut.HandleAsync(new ResetPasswordRequest("expired-token", "N3w!Pass"), CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_or_expired_token");
    }
}

