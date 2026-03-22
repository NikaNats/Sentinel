namespace Sentinel.Tests.Session;

/// <summary>
/// Integration tests for SessionManager with session revocation and DPoP binding validation.
/// </summary>
public class SessionManagerTests
{
    private readonly MockSessionBlacklistCache _blacklist;
    private readonly SessionManager _manager;

    public SessionManagerTests()
    {
        _blacklist = new MockSessionBlacklistCache();
        _manager = new SessionManager(_blacklist);
    }

    [Xunit.Fact]
    public async Task RevokeSessionAsync_WithValidSession_AddsToBlacklist()
    {
        // Arrange
        var sessionId = "sid-123";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(8);

        // Act
        var result = await _manager.RevokeSessionAsync(sessionId, expiresAt);

        // Assert
        result.IsSuccess.Should().BeTrue();
        _blacklist.BlacklistedSessions.Should().Contain(sessionId);
    }

    [Xunit.Fact]
    public async Task IsSessionRevokedAsync_WithBlacklistedSession_ReturnsTrue()
    {
        // Arrange
        var sessionId = "sid-123";
        await _manager.RevokeSessionAsync(sessionId, DateTimeOffset.UtcNow.AddHours(1));

        // Act
        var isRevoked = await _manager.IsSessionRevokedAsync(sessionId);

        // Assert
        isRevoked.Should().BeTrue();
    }

    [Xunit.Fact]
    public async Task IsSessionRevokedAsync_WithActiveSession_ReturnsFalse()
    {
        // Arrange
        var sessionId = "sid-123";

        // Act
        var isRevoked = await _manager.IsSessionRevokedAsync(sessionId);

        // Assert
        isRevoked.Should().BeFalse();
    }

    [Xunit.Fact]
    public async Task RevokeSessionAsync_MultipleRequests_AllBlacklisted()
    {
        // Arrange
        var sessionIds = new[] { "sid-1", "sid-2", "sid-3" };
        var expiresAt = DateTimeOffset.UtcNow.AddHours(8);

        // Act
        foreach (var sessionId in sessionIds)
        {
            await _manager.RevokeSessionAsync(sessionId, expiresAt);
        }

        // Assert
        foreach (var sessionId in sessionIds)
        {
            var isRevoked = await _manager.IsSessionRevokedAsync(sessionId);
            isRevoked.Should().BeTrue();
        }
    }

    [Xunit.Fact]
    public void ValidateDpopBinding_WithMatchingThumbprints_ReturnsTrue()
    {
        // Arrange
        var sessionId = "sid-123";
        var thumbprint = "base64url-thumbprint";

        // Act
        var isValid = SessionManager.ValidateDpopBinding(sessionId, thumbprint, thumbprint);

        // Assert
        isValid.Should().BeTrue();
    }

    [Xunit.Fact]
    public void ValidateDpopBinding_WithMismatchedThumbprints_ReturnsFalse()
    {
        // Arrange
        var sessionId = "sid-123";
        var dpopThumbprint = "base64url-thumbprint-1";
        var sessionThumbprint = "base64url-thumbprint-2";

        // Act
        var isValid = SessionManager.ValidateDpopBinding(sessionId, dpopThumbprint, sessionThumbprint);

        // Assert
        isValid.Should().BeFalse();
    }

    [Xunit.Fact]
    public void ValidateDpopBinding_WithNullSessionThumbprint_ReturnsTrue()
    {
        // Arrange
        var sessionId = "sid-123";
        var dpopThumbprint = "base64url-thumbprint";

        // Act
        var isValid = SessionManager.ValidateDpopBinding(sessionId, dpopThumbprint, null);

        // Assert - session not DPoP-bound, so any proof is acceptable
        isValid.Should().BeTrue();
    }

    [Xunit.Fact]
    public void ValidateDpopBinding_WithEmptySessionThumbprint_ReturnsTrue()
    {
        // Arrange
        var sessionId = "sid-123";
        var dpopThumbprint = "base64url-thumbprint";

        // Act
        var isValid = SessionManager.ValidateDpopBinding(sessionId, dpopThumbprint, string.Empty);

        // Assert
        isValid.Should().BeTrue();
    }

    [Xunit.Fact]
    public void ValidateDpopBinding_CaseSensitive_ReturnsFalse()
    {
        // Arrange
        var sessionId = "sid-123";
        var dpopThumbprint = "BASE64URL-THUMBPRINT";
        var sessionThumbprint = "base64url-thumbprint";

        // Act
        var isValid = SessionManager.ValidateDpopBinding(sessionId, dpopThumbprint, sessionThumbprint);

        // Assert - Base64url is case-sensitive
        isValid.Should().BeFalse();
    }
}
