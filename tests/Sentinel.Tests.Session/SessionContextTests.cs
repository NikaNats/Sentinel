namespace Sentinel.Tests.Session;

/// <summary>
///     High-Assurance Tests for SessionContext Value Object
///     MISSION: Verify security invariants as executable specifications:
///     1. Constructor Hardening: Cannot be "poisoned" with null or empty identifiers
///     2. Deterministic Expiration Boundaries: Exact nanosecond-level precision
///     3. DPoP Binding Integrity: Optional but immutable
///     These tests treat SessionContext as the boundary enforcer between untrusted input
///     and the secure session lifecycle.
/// </summary>
public class SessionContextTests
{
    [Theory(DisplayName = "Constructor rejects invalid session identifiers (Null-Key Attack)")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_WhenSessionIdIsInvalid_MustThrow(string? invalidId)
    {
        // Arrange & Act
#pragma warning disable CA1806 // Do not ignore method results - call IS the test
        Action act = () => _ = new SessionContext(invalidId!, DateTimeOffset.UtcNow);
#pragma warning restore CA1806

        // Assert: Constructor MUST enforce non-null, non-whitespace identifiers
        act.Should()
            .Throw<ArgumentException>()
            .WithParameterName("sessionId",
                "Poisoned SessionContext with null/empty ID could bypass session revocation.");
    }

    [Fact]
    public void Constructor_WithValidSessionId_StoresAndReturnsSessionId()
    {
        // Arrange
        var sessionId = "sid-123";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        // Act
        var context = new SessionContext(sessionId, expiresAt);

        // Assert
        context.SessionId.Should().Be(sessionId);
    }

    [Fact]
    public void Constructor_WithDpopThumbprint_StoresAndReturnsThumbprint()
    {
        // Arrange
        var sessionId = "sid-123";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);
        var thumbprint = "base64url-thumbprint-value";

        // Act
        var context = new SessionContext(sessionId, expiresAt, thumbprint);

        // Assert
        context.DpopThumbprint.Should().Be(thumbprint);
    }

    [Fact]
    public void Constructor_WithoutDpopThumbprint_ReturnsNull()
    {
        // Arrange
        var sessionId = "sid-123";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        // Act
        var context = new SessionContext(sessionId, expiresAt);

        // Assert
        context.DpopThumbprint.Should().BeNull();
    }

    [Fact(DisplayName = "Expiration boundary test: Inclusive equality at exact expiry time")]
    public void IsExpired_ExactlyAtExpiryTime_MustReturnTrue()
    {
        // Arrange: Create a session expiring at a specific time
        var expiryTime = DateTimeOffset.UtcNow;
        var sut = new SessionContext("sid", expiryTime);

        // Act: Check expiration AT the exact boundary
        var result = sut.IsExpired(expiryTime);

        // Assert: SECURITY BOUNDARY MUST BE INCLUSIVE
        // now >= expiresAt is the correct formula (not now > expiresAt)
        // This prevents race conditions where now == expiresAt allows the session
        result.Should().BeTrue(
            "At the exact expiry instant, session MUST be considered expired to prevent use-after-expiry race conditions.");
    }

    [Fact]
    public void IsExpired_OneNanosecondBeforeExpiry_MustReturnFalse()
    {
        // Arrange: Create a session expiring at a specific time
        var expiryTime = DateTimeOffset.UtcNow.AddTicks(1);
        var beforeExpiry = expiryTime.AddTicks(-1);
        var sut = new SessionContext("sid", expiryTime);

        // Act: Check before the boundary
        var result = sut.IsExpired(beforeExpiry);

        // Assert: Session should still be valid
        result.Should().BeFalse("One nanosecond before expiry, session must still be valid.");
    }

    [Theory(DisplayName = "Deterministic boundary testing: relative to reference time")]
    [InlineData(1, true)] // 1 second after expiry = expired
    [InlineData(0, true)] // Exactly at expiry = expired
    [InlineData(-1, false)] // 1 second before expiry = NOT expired
    public void IsExpired_RelativeToExpiryTime_MustReturnExpected(int secondsOffset, bool expectedExpired)
    {
        // Arrange
        var referenceTime = DateTimeOffset.UtcNow;
        var expiresAt = referenceTime;
        var sut = new SessionContext("sid", expiresAt);
        var testTime = expiresAt.AddSeconds(secondsOffset);

        // Act
        var result = sut.IsExpired(testTime);

        // Assert
        result.Should().Be(expectedExpired,
            "Expiration boundary must be deterministic and inclusive at the exact moment.");
    }

    [Fact]
    public void DpopThumbprint_IsImmutable_CannotBeModified()
    {
        // Arrange
        var context = new SessionContext("sid", DateTimeOffset.UtcNow.AddHours(1), "initial-thumbprint");

        // Assert: DpopThumbprint is a property with only a getter (immutable)
        var property = typeof(SessionContext)
            .GetProperty(nameof(SessionContext.DpopThumbprint));

        property.Should().NotBeNull("DPoP thumbprint property must exist");
        property!.GetSetMethod()
            .Should().BeNull("DPoP thumbprint must be immutable after binding.");
    }
}
