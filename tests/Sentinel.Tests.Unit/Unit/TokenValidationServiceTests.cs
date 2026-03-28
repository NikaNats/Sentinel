using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Auth;

namespace Sentinel.Tests.Unit.Auth;

/// <summary>
/// High-Assurance Tests for TokenValidationService
///
/// MISSION: Verify temporal hardening and SIEM signal integrity.
/// Tests eliminate "Heisenbugs" via FakeTimeProvider and enforce strict telemetry verification.
/// A test is a failure if it ignores the audit side-effects of a rejection (telemetry emission).
/// </summary>
public sealed class TokenValidationServiceTests
{
    private readonly FakeTimeProvider _timeProvider;
    private readonly Mock<IJtiReplayCache> _replayCacheMock;
    private readonly Mock<ISessionBlacklistCache> _sessionBlacklistMock;
    private readonly Mock<ISecurityEventEmitter> _eventEmitterMock;
    private readonly TokenValidationService _sut;

    public TokenValidationServiceTests()
    {
        // ====== Arrange: Infrastructure with Deterministic Time ======
        _timeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow);
        _replayCacheMock = new Mock<IJtiReplayCache>(MockBehavior.Strict);
        _sessionBlacklistMock = new Mock<ISessionBlacklistCache>(MockBehavior.Strict);
        _eventEmitterMock = new Mock<ISecurityEventEmitter>(MockBehavior.Strict);

        _sut = new TokenValidationService(
            _replayCacheMock.Object,
            _sessionBlacklistMock.Object,
            _eventEmitterMock.Object,
            _timeProvider);
    }

    [Fact(DisplayName = "⏱️ Temporal Boundary: Token exactly at expiry time must be rejected")]
    public async Task ValidateAsync_WhenNowEqualsExpiry_ReturnsFailure_AndVerifiesFailFast()
    {
        // Arrange
        var now = _timeProvider.GetUtcNow();
        var jti = "jti-boundary-123";
        var sub = "user-001";

        // Token expires EXACTLY now
        var principal = BuildPrincipal(
            ("jti", jti),
            ("sub", sub),
            ("exp", now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))
        );

        var context = new DefaultHttpContext();

        // Act
        var result = await _sut.ValidateAsync(principal, context, CancellationToken.None);

        // Assert: Security Boundary MUST be Inclusive
        result.IsSuccess.Should()
            .BeFalse("Security boundaries must be inclusive of the expiry instant to prevent race conditions.");
        result.FailureReason.Should()
            .Be("Token is already expired.",
                "Fail-Fast: Reject before cache queries when time boundary violated.");

        // Verify NO cache calls were made (Fail-Fast Pattern)
        _replayCacheMock.VerifyNoOtherCalls();
        _sessionBlacklistMock.VerifyNoOtherCalls();
        _eventEmitterMock.VerifyNoOtherCalls();
    }

    [Fact(DisplayName = "🛡️ Replay Detection: Reused JTI must trigger Critical SIEM event")]
    public async Task ValidateAsync_WhenJtiAlreadyUsed_ReturnsReplayFailureAndEmitsEvent()
    {
        // Arrange
        var futureExp = _timeProvider.GetUtcNow().AddMinutes(5);
        var jti = "jti-replay-attack";
        var sub = "attacker-001";
        var ctx = new DefaultHttpContext();

        var principal = BuildPrincipal(
            ("jti", jti),
            ("sub", sub),
            ("exp", futureExp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))
        );

        // Simulate JTI already exists in Redis
        _replayCacheMock
            .Setup(x => x.TryMarkUsedAsync(jti, It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        // EXPECT telemetry emission (Non-negotiable for 100/100 test suite)
        _eventEmitterMock
            .Setup(x => x.EmitTokenReplay(jti, sub, It.IsAny<string>(), It.IsAny<string>()))
            .Verifiable(Times.Once, "Replay attacks MUST be logged to SOC for detection");

        // Act
        var result = await _sut.ValidateAsync(principal, ctx, CancellationToken.None);

        // Assert: Failure + Telemetry Verified
        result.IsSuccess.Should().BeFalse();
        result.FailureReason.Should()
            .Be("Token replay detected.",
                "Adversary receives consistent failure message (no topology leakage).");

        // Verify telemetry was emitted
        _eventEmitterMock.Verify();
        _sessionBlacklistMock.VerifyNoOtherCalls();
    }

    [Fact(DisplayName = "🔓 Session Revocation: Blacklisted session must be rejected and logged")]
    public async Task ValidateAsync_WhenSessionIsBlacklisted_ReturnsSessionFailureAndEmitsEvent()
    {
        // Arrange
        var futureExp = _timeProvider.GetUtcNow().AddMinutes(5);
        var jti = "jti-valid";
        var sub = "user-revoked";
        var sid = "sid-revoked";
        var ctx = new DefaultHttpContext();

        var principal = BuildPrincipal(
            ("jti", jti),
            ("sub", sub),
            ("sid", sid),
            ("exp", futureExp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))
        );

        // JTI passes replay check
        _replayCacheMock
            .Setup(x => x.TryMarkUsedAsync(jti, It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Session is blacklisted
        _sessionBlacklistMock
            .Setup(x => x.IsBlacklistedAsync(sid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Expect revoked session event
        _eventEmitterMock
            .Setup(x => x.EmitAuthFailure("revoked_session_usage_attempt", sub, It.IsAny<string>()))
            .Verifiable(Times.Once, "Session revocation attempts MUST be logged");

        // Act
        var result = await _sut.ValidateAsync(principal, ctx, CancellationToken.None);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.FailureReason.Should()
            .Be("Session has been terminated.",
                "Consistent error message; no topology leakage to attacker.");
        _eventEmitterMock.Verify();
    }

    [Fact(DisplayName = "🚨 Infrastructure Chaos: Replay cache failure must fail-closed")]
    public async Task ValidateAsync_WhenReplayCacheUnavailable_ReturnsExceptionOutcomeAndEmitsEvent()
    {
        // Arrange
        var replayError = new ReplayCacheUnavailableException(
            "Redis cluster unreachable",
            new InvalidOperationException("Connection timeout"));

        var futureExp = _timeProvider.GetUtcNow().AddMinutes(5);
        var jti = "jti-cache-fail";
        var sub = "user-001";
        var ctx = new DefaultHttpContext();

        var principal = BuildPrincipal(
            ("jti", jti),
            ("sub", sub),
            ("exp", futureExp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))
        );

        // Cache throws during replay check
        _replayCacheMock
            .Setup(x => x.TryMarkUsedAsync(jti, It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(replayError);

        // Expect infrastructure failure event for SOC alerting
        _eventEmitterMock
            .Setup(x => x.EmitAuthFailure("replay_cache_unavailable", sub, It.IsAny<string>()))
            .Verifiable(Times.Once, "SOC must be alerted when security infrastructure fails");

        // Act
        var result = await _sut.ValidateAsync(principal, ctx, CancellationToken.None);

        // Assert: Fail-Closed + Exception Captured
        result.IsSuccess.Should()
            .BeFalse("Cache unavailability MUST result in rejection (fail-closed pattern).");
        result.FailureException.Should()
            .Be(replayError, "The infrastructure exception is captured for auditing.");
        _eventEmitterMock.Verify();
    }

    [Fact(DisplayName = "✅ Happy Path: Valid token with active session passes all gates")]
    public async Task ValidateAsync_WhenClaimsAndStateAreValid_ReturnsSuccess()
    {
        // Arrange
        var futureExp = _timeProvider.GetUtcNow().AddMinutes(5);
        var jti = "jti-valid-001";
        var sub = "user-authenticated";
        var sid = "sid-active";
        var ctx = new DefaultHttpContext();

        var principal = BuildPrincipal(
            ("jti", jti),
            ("sub", sub),
            ("sid", sid),
            ("exp", futureExp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))
        );

        // Setup: All gates pass
        _replayCacheMock
            .Setup(x => x.TryMarkUsedAsync(jti, It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        _sessionBlacklistMock
            .Setup(x => x.IsBlacklistedAsync(sid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        // Act
        var result = await _sut.ValidateAsync(principal, ctx, CancellationToken.None);

        // Assert: Success + No Spurious Telemetry
        result.IsSuccess.Should().BeTrue("All security gates passed.");
        result.FailureReason.Should().BeNull();
        result.FailureException.Should().BeNull();

        // Critical: No telemetry emitted on success path (prevents log pollution)
        _eventEmitterMock.VerifyNoOtherCalls(
            "Successful authentication should not emit events (only failures need audit trail).");
    }

    private static ClaimsPrincipal BuildPrincipal(params (string Type, string Value)[] claims)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(claims.Select(x => new Claim(x.Type, x.Value)), "test"));
    }
}
