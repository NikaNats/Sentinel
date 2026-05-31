using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Tests.Session.Helpers;

namespace Sentinel.Tests.Session;

/// <summary>
///     High-Assurance Tests for SessionManager
///     MISSION: Verify that SessionManager is a "Fail-Closed" component that:
///     1. MUST reject when infrastructure is unavailable (Fail-Closed)
///     2. MUST NOT leak topology details in error messages (Sanitization)
///     3. MUST use byte-exact comparisons for security-sensitive operations (Ordinal)
///     4. MUST reject requests when required DPoP binding is missing (Zero Trust)
///     These are security tests, not functional tests. We're verifying the system
///     behaves CORRECTLY when things go wrong, not just when they work normally.
/// </summary>
public class SessionManagerTests
{
    private readonly MockSessionBlacklistCache _blacklist;
    private readonly SessionManager _manager;
    private readonly IOptions<SessionManagementOptions> _options;
    private static CancellationToken TestCancellationToken => TestContext.Current.CancellationToken;

    public SessionManagerTests()
    {
        _blacklist = new MockSessionBlacklistCache();
        _options = Options.Create(new SessionManagementOptions { RequireDpopBinding = true });
        _manager = new SessionManager(_blacklist, _options, NullLogger<SessionManager>.Instance);
    }

    [Fact(DisplayName = "Fail-Closed: Revocation fails when cache is down")]
    public async Task RevokeSessionAsync_WhenCacheIsDown_MustReturnFailClosedResult()
    {
        // Arrange: Simulate infrastructure failure (Redis down, network error, etc.)
        _blacklist.ExceptionToThrow = new InvalidOperationException("Redis cluster unavailable");

        // Act
        var result = await _manager.RevokeSessionAsync("sid_123", DateTimeOffset.UtcNow.AddHours(1), TestCancellationToken);

        // Assert: SECURITY INVARIANT - Fail Closed
        result.IsSuccess.Should()
            .BeFalse(
                "If the system cannot guarantee a session is revoked, it MUST fail the request. \n" +
                "Allowing operations when the cache is down violates the Zero Trust principle.");
    }

    [Fact]
    public async Task RevokeSessionAsync_WhenCacheIsDown_MustNotLeakTopologyDetails()
    {
        // Arrange
        var sensitiveError = new Exception("Internal: Redis cluster 10.0.1.5:6379 unavailable, auth token expired");
        _blacklist.ExceptionToThrow = sensitiveError;

        // Act
        var result = await _manager.RevokeSessionAsync("sid_123", DateTimeOffset.UtcNow.AddHours(1), TestCancellationToken);

        // Assert: Error message must be SANITIZED (Fail-Closed + Secure)
        // The original exception details (IP, port, auth status) MUST NOT appear in the result
        result.ErrorMessage.Should()
            .Be("revocation_unavailable",
                "SecurityResult error messages must be sanitized to avoid leaking topology, \n" +
                "auth credentials, or other infrastructure details to attackers.");
    }

    [Fact]
    public async Task RevokeSessionAsync_WithValidSession_AddsToBlacklist()
    {
        // Arrange
        var sessionId = "sid-123";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(8);

        // Act
        var result = await _manager.RevokeSessionAsync(sessionId, expiresAt, TestCancellationToken);

        // Assert
        result.IsSuccess.Should().BeTrue();
        _blacklist.BlacklistedSessions.Should().Contain(sessionId);
    }

    [Fact(DisplayName = "Fail-Closed: Query assumes session is revoked when cache is down")]
    public async Task IsSessionRevokedAsync_WhenCacheIsDown_MustFailClosed()
    {
        // Arrange
        _blacklist.ExceptionToThrow = new InvalidOperationException("Connection Reset by Peer");

        // Act
        var result = await _manager.IsSessionRevokedAsync("sid_123", TestCancellationToken);

        // Assert: SECURITY INVARIANT - Fail Closed
        result.IsSuccess.Should()
            .BeFalse(
                "If cache is unavailable, we CANNOT verify whether a session was revoked. \n" +
                "The system must assume the session is UNSAFE and reject the request.");
    }

    [Fact]
    public async Task IsSessionRevokedAsync_WithBlacklistedSession_ReturnsTrue()
    {
        // Arrange
        var sessionId = "sid-123";
        await _manager.RevokeSessionAsync(sessionId, DateTimeOffset.UtcNow.AddHours(1), TestCancellationToken);

        // Act
        var result = await _manager.IsSessionRevokedAsync(sessionId, TestCancellationToken);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Value.Should().BeTrue("Session must be marked as revoked.");
    }

    [Fact]
    public async Task IsSessionRevokedAsync_WithActiveSession_ReturnsFalse()
    {
        // Arrange
        var sessionId = "sid-123";

        // Act
        var result = await _manager.IsSessionRevokedAsync(sessionId, TestCancellationToken);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Value.Should().BeFalse("Active session must not be marked as revoked.");
    }

    [Fact]
    public async Task RevokeSessionAsync_MultipleRequests_AllBlacklisted()
    {
        // Arrange
        var sessionIds = new[] { "sid-1", "sid-2", "sid-3" };
        var expiresAt = DateTimeOffset.UtcNow.AddHours(8);

        // Act
        foreach (var sessionId in sessionIds)
        {
            var result = await _manager.RevokeSessionAsync(sessionId, expiresAt, TestCancellationToken);
            result.IsSuccess.Should().BeTrue();
        }

        // Assert
        foreach (var sessionId in sessionIds)
        {
            var result = await _manager.IsSessionRevokedAsync(sessionId, TestCancellationToken);
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().BeTrue();
        }
    }

    [Theory(DisplayName = "Cryptographic comparison must be byte-exact (Ordinal)")]
    [InlineData("match", "match", true)]
    [InlineData("MATCH", "match", false)] // Case mismatch = fail (prevents Unicode collisions)
    [InlineData("mismatch", "other", false)]
    public void ValidateDpopBinding_MustUseOrdinalComparison(string proof, string stored, bool expected)
    {
        // Act
        var result = _manager.ValidateDpopBinding(proof, stored);

        // Assert
        result.Should().Be(expected,
            "Thumbprint matching must be byte-exact (Ordinal) to prevent collision-bypass attacks. \n" +
            "Unicode normalization (e.g., é vs é) would create equivalence class exploits.");
    }

    [Fact(DisplayName = "Zero Trust: DPoP binding required but missing = REJECT")]
    public void ValidateDpopBinding_WhenBindingIsRequiredButMissing_MustReject()
    {
        // Arrange: RequireDpopBinding=true (already set in constructor)
        var dpopThumbprint = "valid-thumbprint";
        var sessionThumbprint = (string?)null; // Session does NOT have DPoP binding

        // Act
        var result = _manager.ValidateDpopBinding(dpopThumbprint, sessionThumbprint);

        // Assert: SECURITY INVARIANT - Zero Trust
        result.Should().BeFalse(
            "When RequireDpopBinding is enabled and session has no thumbprint, \n" +
            "request MUST be rejected. Allowing unbound proofs violates Zero Trust.");
    }

    [Fact]
    public void ValidateDpopBinding_WithMatchingThumbprints_ReturnsTrue()
    {
        // Arrange
        var thumbprint = "base64url-thumbprint";

        // Act
        var result = _manager.ValidateDpopBinding(thumbprint, thumbprint);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void ValidateDpopBinding_WithMismatchedThumbprints_ReturnsFalse()
    {
        // Arrange
        var dpopThumbprint = "base64url-thumbprint-1";
        var sessionThumbprint = "base64url-thumbprint-2";

        // Act
        var result = _manager.ValidateDpopBinding(dpopThumbprint, sessionThumbprint);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ValidateDpopBinding_WithNullSessionThumbprint_RejectsWhenRequireDpopBindingIsTrue()
    {
        // Arrange: RequireDpopBinding=true (default from constructor)
        var dpopThumbprint = "base64url-thumbprint";
        var sessionThumbprint = (string?)null;

        // Act
        var result = _manager.ValidateDpopBinding(dpopThumbprint, sessionThumbprint);

        // Assert: When RequireDpopBinding is enabled, null binding = rejection
        result.Should().BeFalse("DPoP binding is required but session has no binding.");
    }

    [Fact]
    public void ValidateDpopBinding_WithEmptySessionThumbprint_RejectsWhenRequireDpopBindingIsTrue()
    {
        // Arrange: RequireDpopBinding=true (default from constructor)
        var dpopThumbprint = "base64url-thumbprint";
        var sessionThumbprint = string.Empty;

        // Act
        var result = _manager.ValidateDpopBinding(dpopThumbprint, sessionThumbprint);

        // Assert: Empty is treated as no binding
        result.Should().BeFalse("DPoP binding is required but session has empty binding.");
    }

    [Fact(DisplayName = "Case sensitivity: Base64url IS case-sensitive")]
    public void ValidateDpopBinding_CaseSensitive_DifferentCase_ReturnsFalse()
    {
        // Arrange: Uppercase vs. lowercase
        var dpopThumbprint = "BASE64URL-THUMBPRINT";
        var sessionThumbprint = "base64url-thumbprint";

        // Act
        var result = _manager.ValidateDpopBinding(dpopThumbprint, sessionThumbprint);

        // Assert: Base64url encoding is case-sensitive (Ordinal comparison)
        result.Should().BeFalse(
            "Base64url encoding is strictly case-sensitive. \n" +
            "Case-insensitive comparison (e.g., Invariant culture) would allow collision attacks.");
    }
}
