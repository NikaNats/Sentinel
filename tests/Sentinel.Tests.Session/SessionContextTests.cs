namespace Sentinel.Tests.Session;

/// <summary>
/// Tests for SessionContext value object initialization and expiration checks.
/// </summary>
public class SessionContextTests
{
    [Xunit.Fact]
    public void Constructor_WithSessionId_StoresAndReturnsSessionId()
    {
        // Arrange
        var sessionId = "sid-123";

        // Act
        var context = new SessionContext(sessionId);

        // Assert
        context.SessionId.Should().Be(sessionId);
    }

    [Xunit.Fact]
    public void Constructor_WithDpopThumbprint_StoresAndReturnsDpopThumbprint()
    {
        // Arrange
        var sessionId = "sid-123";
        var thumbprint = "base64url-thumbprint-value";

        // Act
        var context = new SessionContext(sessionId, thumbprint);

        // Assert
        context.DpopThumbprint.Should().Be(thumbprint);
    }

    [Xunit.Fact]
    public void Constructor_WithoutDpopThumbprint_ReturnNull()
    {
        // Arrange
        var sessionId = "sid-123";

        // Act
        var context = new SessionContext(sessionId);

        // Assert
        context.DpopThumbprint.Should().BeNull();
    }

    [Xunit.Fact]
    public void Constructor_WithExpiresAt_StoresAndReturnsExpiresAt()
    {
        // Arrange
        var sessionId = "sid-123";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(4);

        // Act
        var context = new SessionContext(sessionId, null, expiresAt);

        // Assert
        context.ExpiresAt.Should().Be(expiresAt);
    }

    [Xunit.Fact]
    public void Constructor_WithoutExpiresAt_DefaultsTo8Hours()
    {
        // Arrange
        var sessionId = "sid-123";
        var beforeCreation = DateTimeOffset.UtcNow.AddHours(8);

        // Act
        var context = new SessionContext(sessionId);
        var afterCreation = DateTimeOffset.UtcNow.AddHours(8).AddSeconds(1);

        // Assert
        Assert.InRange(context.ExpiresAt, beforeCreation, afterCreation);
    }

    [Xunit.Fact]
    public void IsExpired_WithFutureTime_ReturnsFalse()
    {
        // Arrange
        var context = new SessionContext(
            "sid-123",
            expiresAt: DateTimeOffset.UtcNow.AddHours(1));
        var now = DateTimeOffset.UtcNow;

        // Act
        var isExpired = context.IsExpired(now);

        // Assert
        isExpired.Should().BeFalse();
    }

    [Xunit.Fact]
    public void IsExpired_WithPastTime_ReturnsTrue()
    {
        // Arrange
        var context = new SessionContext(
            "sid-123",
            expiresAt: DateTimeOffset.UtcNow.AddHours(-1));
        var now = DateTimeOffset.UtcNow;

        // Act
        var isExpired = context.IsExpired(now);

        // Assert
        isExpired.Should().BeTrue();
    }
}
