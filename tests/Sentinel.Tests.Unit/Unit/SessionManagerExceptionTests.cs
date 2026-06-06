using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Security.Abstractions.Session;
using Sentinel.Session;

namespace Sentinel.Tests.Unit.Unit;

public sealed class SessionManagerExceptionTests
{
    private static SessionManager CreateSut(Mock<ISessionBlacklistCache> cache, bool requireDpopBinding = true)
    {
        var options = Microsoft.Extensions.Options.Options.Create(
            new SessionManagementOptions { RequireDpopBinding = requireDpopBinding });
        return new SessionManager(cache.Object, options, NullLogger<SessionManager>.Instance);
    }

    [Fact]
    public async Task RevokeSessionAsync_WhenCacheThrows_ReturnsFailClosedResult()
    {
        var cacheMock = new Mock<ISessionBlacklistCache>();
        cacheMock
            .Setup(x => x.BlacklistSessionAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Redis cluster down"));

        var sut = CreateSut(cacheMock);

        var result = await sut.RevokeSessionAsync("sid-123", DateTimeOffset.UtcNow);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be("revocation_unavailable");
    }

    [Fact]
    public async Task RevokeSessionAsync_WhenCancelled_ThrowsOperationCanceledException()
    {
        var cacheMock = new Mock<ISessionBlacklistCache>();
        cacheMock
            .Setup(x => x.BlacklistSessionAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());

        var sut = CreateSut(cacheMock);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            sut.RevokeSessionAsync("sid-123", DateTimeOffset.UtcNow, cts.Token));
    }

    [Fact]
    public async Task IsSessionRevokedAsync_WhenCacheReturnsTrue_ReturnsSuccessWithTrue()
    {
        var cacheMock = new Mock<ISessionBlacklistCache>();
        cacheMock
            .Setup(x => x.IsBlacklistedAsync("sid-revoked", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var sut = CreateSut(cacheMock);

        var result = await sut.IsSessionRevokedAsync("sid-revoked");

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().BeTrue();
    }

    [Fact]
    public async Task IsSessionRevokedAsync_WhenCacheThrows_ReturnsFailClosedResult()
    {
        var cacheMock = new Mock<ISessionBlacklistCache>();
        cacheMock
            .Setup(x => x.IsBlacklistedAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Cache unavailable"));

        var sut = CreateSut(cacheMock);

        var result = await sut.IsSessionRevokedAsync("sid-123");

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be("revocation_check_unavailable");
    }

    [Fact]
    public void ValidateDpopBinding_WhenThumbprintsMatch_ReturnsTrue()
    {
        var cacheMock = new Mock<ISessionBlacklistCache>();
        var sut = CreateSut(cacheMock);

        var result = sut.ValidateDpopBinding("thumbprint-abc", "thumbprint-abc");

        result.Should().BeTrue();
    }

    [Fact]
    public void ValidateDpopBinding_WhenSessionThumbprintMissingAndBindingRequired_ReturnsFalse()
    {
        var cacheMock = new Mock<ISessionBlacklistCache>();
        var sut = CreateSut(cacheMock);

        var result = sut.ValidateDpopBinding("thumbprint-abc", null);

        result.Should().BeFalse();
    }

    [Fact]
    public void ValidateDpopBinding_WhenSessionThumbprintMissingAndBindingOptional_ReturnsTrue()
    {
        var cacheMock = new Mock<ISessionBlacklistCache>();
        var sut = CreateSut(cacheMock, false);

        var result = sut.ValidateDpopBinding("thumbprint-abc", null);

        result.Should().BeTrue();
    }
}
