using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;

namespace Sentinel.Tests.SSF;

/// <summary>
///     High-assurance test suite for SsfEventProcessor (Security Event Token handler).
///     This suite implements adversarial testing patterns to verify:
///     1. Correct interpretation of CAEP (Continuous Access Evaluation Profile) payloads
///     2. Proper temporal boundary enforcement (replay attack prevention)
///     3. Fail-closed security posture (infrastructure unavailability)
///     4. Graceful degradation under malformed input
///     SECURITY PRINCIPLES:
///     - Temporal Hardening: Tests verify exact iat (issued-at) boundaries
///     - Fail-Closed: System returns false (deny) on any infrastructure failure
///     - Logical Completeness: Both sid (session) and sub (user) revocation paths tested
///     - Real-World Context: Uses IANA-registered CAEP event URIs
/// </summary>
public sealed class SsfEventProcessorTests
{
    // IANA-registered CAEP event URIs per the specification
    private const string SessionRevokedUri = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

    private const string UserStatusChangedUri =
        "https://schemas.openid.net/secevent/caep/event-type/user-status-changed";

    private readonly MockSessionBlacklistCache _cache;
    private readonly IOptions<SsfProcessingOptions> _options;
    private readonly MockAuthRevocationService _revocation;
    private readonly SsfEventProcessor _sut;

    private readonly MockSsfTokenValidator _validator;

    public SsfEventProcessorTests()
    {
        _validator = new MockSsfTokenValidator();
        _cache = MockSessionBlacklistCache.Create();
        _revocation = new MockAuthRevocationService();

        _options = Options.Create(new SsfProcessingOptions
        {
            MaxEventAgeSeconds = 300,
            AllowedClockSkewSeconds = 60,
            SessionRevocationTtlSeconds = 3600
        });

        _sut = new SsfEventProcessor(
            _validator,
            _cache,
            _revocation,
            _options,
            NullLogger<SsfEventProcessor>.Instance,
            TimeProvider.System);
    }

    /// <summary>
    ///     Tests: Valid CAEP session-revoked event adds the specific session to blacklist.
    ///     CAEP Logic: A 'session-revoked' event with a 'sid' (session ID) must invalidate
    ///     only that specific session, not the entire user account.
    /// </summary>
    [Fact(DisplayName = "✅ Valid Session-Revoked Event Adds Session to Blacklist")]
    public async Task ProcessAsync_WithValidSessionRevokedEvent_AddsSessionToBlacklist()
    {
        // Arrange: Construct a valid CAEP session-revoked payload
        const string targetSid = "sess-7890-abc";
        var events = new Dictionary<string, JsonElement>
        {
            [SessionRevokedUri] = MockSsfTokenValidator.CreateCaepPayload(new { sid = targetSid })
        };

        _validator.CustomResult = SsfValidationResult.Success(CreateToken(events));

        // Act
        var result = await _sut.ProcessAsync("valid-session-revoke-token");

        // Assert
        result.IsSuccess.Should().BeTrue("Valid CAEP events must process successfully");
        (await _cache.IsBlacklistedAsync(targetSid)).Should().BeTrue(
            "The processor must add the specific session ID to the blacklist per CAEP spec");
    }

    /// <summary>
    ///     Tests: CAEP event without 'sid' triggers global subject-level revocation.
    ///     CAEP Logic: A 'session-revoked' event with ONLY 'sub' (subject/user) revokes
    ///     all sessions for that user account, not just one session.
    /// </summary>
    [Fact(DisplayName = "🔐 Subject-Level Revocation Triggers Global Logout")]
    public async Task ProcessAsync_WithSubjectRevokedEvent_TriggersGlobalRevocation()
    {
        // Arrange: CAEP event with 'sub' but no 'sid' = full subject revocation
        const string targetSub = "user-auth0|5e3b9c88-1234";
        var events = new Dictionary<string, JsonElement>
        {
            [SessionRevokedUri] = MockSsfTokenValidator.CreateCaepPayload(new { sub = targetSub })
        };

        _validator.CustomResult = SsfValidationResult.Success(CreateToken(events, targetSub));

        // Act
        var result = await _sut.ProcessAsync("subject-revoke-token");

        // Assert
        result.IsSuccess.Should().BeTrue();
        _revocation.WasSubjectRevoked(targetSub).Should().BeTrue(
            "A CAEP signal targeting a subject (not a session) must trigger global session revocation");
    }

    /// <summary>
    ///     Tests: Temporal boundary enforcement against replayed or stale tokens.
    ///     SECURITY: SET tokens outside the validity window (too old or too new) must
    ///     be rejected to prevent replay attacks and clock skew exploits.
    ///     RFC 8417 (SET) requires: (now - MaxEventAgeSeconds) is less-than-or-equal-to iat is less-than-or-equal-to (now +
    ///     AllowedClockSkewSeconds)
    /// </summary>
    [Theory(DisplayName = "⏱️ Temporal Boundary Tests: Enforce SET Token Age & Clock Skew")]
    [InlineData(-600, "Stale token (10 mins old, exceeds 5-min max window)")]
    [InlineData(-300, "At boundary: exactly MaxEventAgeSeconds old")]
    [InlineData(120, "Clock skew attack: token issued 2 mins in the future")]
    public async Task ProcessAsync_WhenTokenViolatesTemporalBoundaries_ReturnsFailure(
        int secondsOffset,
        string scenario)
    {
        // Arrange: Create a token with deliberately wrong iat
        var issuedAt = DateTimeOffset.UtcNow.AddSeconds(secondsOffset).ToUnixTimeSeconds();
        var token = CreateToken(new Dictionary<string, JsonElement>(), issuedAt: issuedAt);
        _validator.CustomResult = SsfValidationResult.Success(token);

        // Act
        var result = await _sut.ProcessAsync("temporal-boundary-token");

        // Assert - Stale and future-dated tokens must be rejected
        var shouldFail = secondsOffset < -300 || secondsOffset > 60;
        result.IsSuccess.Should().Be(!shouldFail,
            $"Test: {scenario} — Tokens outside the valid window must be rejected to prevent replay");
    }

    /// <summary>
    ///     Tests: System fails-closed when cache/database is unavailable.
    ///     SECURITY PRINCIPLE: If the processor cannot guarantee that the security action
    ///     (blacklisting a session) succeeded, it MUST return failure. This signals to the
    ///     issuer (Keycloak) that the event wasn't processed, prompting a retry.
    ///     Returning success on infrastructure failure is a critical security vulnerability
    ///     because the access token would be leaked despite a revocation signal.
    /// </summary>
    [Fact(DisplayName = "⚠️ Fail-Closed: Cache Unavailability Returns Failure")]
    public async Task ProcessAsync_WhenCacheIsUnavailable_FailsClosed()
    {
        // Arrange: Valid event, but the cache will throw during blacklist
        var events = new Dictionary<string, JsonElement>
        {
            [SessionRevokedUri] = MockSsfTokenValidator.CreateCaepPayload(new { sid = "test-sess" })
        };
        _validator.CustomResult = SsfValidationResult.Success(CreateToken(events));

        // Create a processor with a cache that fails
        var failingCache = new Mock<ISessionBlacklistCache>();
        failingCache
            .Setup(x => x.BlacklistSessionAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Redis connection reset by peer"));

        var processorWithFailingCache = new SsfEventProcessor(
            _validator,
            failingCache.Object,
            _revocation,
            _options,
            NullLogger<SsfEventProcessor>.Instance,
            TimeProvider.System);

        // Act
        var result = await processorWithFailingCache.ProcessAsync("valid-but-infrastructure-fails");

        // Assert
        result.IsSuccess.Should().BeFalse(
            "The processor MUST return failure if the security action cannot be guaranteed. " +
            "Returning success on error would allow revocation signals to be silently dropped.");
    }

    /// <summary>
    ///     Tests: Malformed CAEP event payloads are gracefully rejected.
    ///     ROBUSTNESS: Even if the SET token passes cryptographic validation,
    ///     the event structure might be corrupted or invalid. The processor must
    ///     detect this without crashing and return a sensible error.
    /// </summary>
    [Fact(DisplayName = "❌ Malformed Event Payload Returns Failure")]
    public async Task ProcessAsync_WithMalformedEventPayload_ReturnsFailure()
    {
        // Arrange: Send a CAEP event with invalid structure (integer instead of object)
        var events = new Dictionary<string, JsonElement>
        {
            [SessionRevokedUri] = MockSsfTokenValidator.CreateCaepPayload(12345) // Invalid: should be an object
        };
        _validator.CustomResult = SsfValidationResult.Success(CreateToken(events));

        // Act
        var result = await _sut.ProcessAsync("malformed-event-token");

        // Assert
        result.IsSuccess.Should().BeFalse(
            "Malformed event payloads must trigger processing failure, not silently skip the event");
    }

    /// <summary>
    ///     Tests: Multiple events in a single SET token are all processed.
    ///     SPECIFICATION: A SET token can contain multiple events (e.g., both
    ///     session-revoked and user-status-changed). The processor must handle all of them.
    /// </summary>
    [Fact(DisplayName = "📦 Multiple CAEP Events in Single Token")]
    public async Task ProcessAsync_WithMultipleEvents_ProcessesAll()
    {
        // Arrange: SET token with both session-revoked and user-status-changed
        const string targetSid = "sess-multi-1";
        const string targetSub = "user-multi-1";

        var events = new Dictionary<string, JsonElement>
        {
            [SessionRevokedUri] = MockSsfTokenValidator.CreateCaepPayload(new { sid = targetSid }),
            [UserStatusChangedUri] = MockSsfTokenValidator.CreateCaepPayload(new { sub = targetSub })
        };

        _validator.CustomResult = SsfValidationResult.Success(CreateToken(events, targetSub));

        // Act
        var result = await _sut.ProcessAsync("multi-event-token");

        // Assert
        result.IsSuccess.Should().BeTrue();
        (await _cache.IsBlacklistedAsync(targetSid)).Should().BeTrue("First event should be processed");
        _revocation.WasSubjectRevoked(targetSub).Should().BeTrue("Second event should be processed");
    }

    /// <summary>
    ///     Tests: Empty event dictionary (valid token, no events) is handled safely.
    ///     This is technically valid per the spec but represents a no-op from the issuer.
    /// </summary>
    [Fact(DisplayName = "✓ Empty Event Token (No-Op) Returns Success")]
    public async Task ProcessAsync_WithNoEvents_ReturnsSuccess()
    {
        // Arrange
        _validator.CustomResult = SsfValidationResult.Success(CreateToken(new Dictionary<string, JsonElement>()));

        // Act
        var result = await _sut.ProcessAsync("empty-events-token");

        // Assert
        result.IsSuccess.Should().BeTrue("A token with no events is valid but represents a no-op");
    }

    // Helper: Creates a token with full control over temporal and event values
    private static SsfEventToken CreateToken(
        Dictionary<string, JsonElement> events,
        string sub = "user-1",
        long? issuedAt = null) =>
        new(
            "https://idp.sentinel.io",
            issuedAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            $"evt-{Guid.NewGuid():N}",
            "sentinel-api",
            sub,
            events);
}
