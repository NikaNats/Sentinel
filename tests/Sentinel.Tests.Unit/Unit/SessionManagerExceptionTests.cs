using Moq;
using Sentinel.Security.Abstractions.Session;
using Sentinel.Session;
using FluentAssertions;

namespace Sentinel.Tests.Unit.Session;

public sealed class SessionManagerExceptionTests
{
    [Fact]
    public async Task RevokeSessionAsync_WhenCacheThrows_ReturnsFailClosedSecurityResult()
    {
        // Arrange
        var cacheMock = new Mock<ISessionBlacklistCache>();
        cacheMock
            .Setup(x => x.BlacklistSessionAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Redis cluster down"));

        var sut = new SessionManager(cacheMock.Object);

        // Act
        var result = await sut.RevokeSessionAsync("sid-123", DateTimeOffset.UtcNow);

        // Assert
        result.IsSuccess.Should().BeFalse("Failure should be returned when cache throws");
        result.ErrorMessage.Should().Contain("revocation_unavailable");
        result.ErrorMessage.Should().Contain("Redis cluster down");
    }

    [Fact]
    public async Task RevokeSessionAsync_WhenCancelled_ThrowsOperationCanceledException()
    {
        // Arrange
        var cacheMock = new Mock<ISessionBlacklistCache>();
        cacheMock
            .Setup(x => x.BlacklistSessionAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());

        var sut = new SessionManager(cacheMock.Object);
        var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act & Assert
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            sut.RevokeSessionAsync("sid-123", DateTimeOffset.UtcNow, cts.Token));
    }

    [Fact]
    public async Task RevokeSessionAsync_WithTimeoutException_ReturnsFailed()
    {
        // Arrange
        var cacheMock = new Mock<ISessionBlacklistCache>();
        cacheMock
            .Setup(x => x.BlacklistSessionAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TimeoutException("Cache timeout"));

        var sut = new SessionManager(cacheMock.Object);

        // Act
        var result = await sut.RevokeSessionAsync("sid-456", DateTimeOffset.UtcNow);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Contain("revocation_unavailable");
        result.ErrorMessage.Should().Contain("Cache timeout");
    }

    [Fact]
    public async Task RevokeSessionAsync_WithValidInput_Succeeds()
    {
        // Arrange
        var cacheMock = new Mock<ISessionBlacklistCache>();
        cacheMock
            .Setup(x => x.BlacklistSessionAsync("sid-789", It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var sut = new SessionManager(cacheMock.Object);
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(30);

        // Act
        var result = await sut.RevokeSessionAsync("sid-789", expiresAt);

        // Assert
        result.IsSuccess.Should().BeTrue();
        cacheMock.Verify(
            x => x.BlacklistSessionAsync("sid-789", expiresAt, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task IsSessionRevokedAsync_WhenCacheReturnsTrue_ReturnsTrueForBlacklisted()
    {
        // Arrange
        var cacheMock = new Mock<ISessionBlacklistCache>();
        cacheMock
            .Setup(x => x.IsBlacklistedAsync("sid-revoked", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var sut = new SessionManager(cacheMock.Object);

        // Act
        var isRevoked = await sut.IsSessionRevokedAsync("sid-revoked");

        // Assert
        isRevoked.Should().BeTrue();
    }

    [Fact]
    public async Task IsSessionRevokedAsync_WhenCacheReturnsFalse_ReturnsFalseForActive()
    {
        // Arrange
        var cacheMock = new Mock<ISessionBlacklistCache>();
        cacheMock
            .Setup(x => x.IsBlacklistedAsync("sid-active", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var sut = new SessionManager(cacheMock.Object);

        // Act
        var isRevoked = await sut.IsSessionRevokedAsync("sid-active");

        // Assert
        isRevoked.Should().BeFalse();
    }

    [Fact]
    public async Task IsSessionRevokedAsync_WhenCacheThrows_PropagatesException()
    {
        // Arrange
        var cacheMock = new Mock<ISessionBlacklistCache>();
        cacheMock
            .Setup(x => x.IsBlacklistedAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Cache unavailable"));

        var sut = new SessionManager(cacheMock.Object);

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => sut.IsSessionRevokedAsync("sid-123"));
    }

    [Fact]
    public void ValidateDpopBinding_WhenThumbprintsMatch_ReturnsTrue()
    {
        // Act
        var result = SessionManager.ValidateDpopBinding("sid-123", "thumbprint-abc", "thumbprint-abc");

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void ValidateDpopBinding_WhenThumbprintsDontMatch_ReturnsFalse()
    {
        // Act
        var result = SessionManager.ValidateDpopBinding("sid-123", "thumbprint-abc", "thumbprint-xyz");

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ValidateDpopBinding_WhenSessionThumbprintIsNull_ReturnsTrue()
    {
        // Arrange - Session doesn't have DPoP binding (e.g., non-browser clients)
        // Act
        var result = SessionManager.ValidateDpopBinding("sid-123", "thumbprint-abc", null);

        // Assert
        result.Should().BeTrue("Non-DPoP-bound sessions should pass");
    }

    [Fact]
    public void ValidateDpopBinding_WhenSessionThumbprintIsEmpty_ReturnsTrue()
    {
        // Act
        var result = SessionManager.ValidateDpopBinding("sid-123", "thumbprint-abc", "");

        // Assert
        result.Should().BeTrue("Empty binding means DPoP not required");
    }

    [Fact]
    public async Task RevokeSessionAsync_WithDatabaseException_ReturnsFailed()
    {
        // Arrange
        var cacheMock = new Mock<ISessionBlacklistCache>();
        cacheMock
            .Setup(x => x.BlacklistSessionAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Database connection failed"));

        var sut = new SessionManager(cacheMock.Object);

        // Act
        var result = await sut.RevokeSessionAsync("sid-db-error", DateTimeOffset.UtcNow);

        // Assert
        result.IsSuccess.Should().BeFalse("Database exception should fail closed");
        result.ErrorMessage.Should().Contain("revocation_unavailable");
        result.ErrorMessage.Should().Contain("Database connection failed");
    }

    [Fact]
    public async Task RevokeSessionAsync_MultipleCallsWithSameSession_AllSucceed()
    {
        // Arrange
        var cacheMock = new Mock<ISessionBlacklistCache>();
        cacheMock
            .Setup(x => x.BlacklistSessionAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var sut = new SessionManager(cacheMock.Object);

        // Act
        var result1 = await sut.RevokeSessionAsync("sid-multi", DateTimeOffset.UtcNow);
        var result2 = await sut.RevokeSessionAsync("sid-multi", DateTimeOffset.UtcNow);

        // Assert
        result1.IsSuccess.Should().BeTrue();
        result2.IsSuccess.Should().BeTrue();
        cacheMock.Verify(
            x => x.BlacklistSessionAsync("sid-multi", It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.Exactly(2));
    }
}
