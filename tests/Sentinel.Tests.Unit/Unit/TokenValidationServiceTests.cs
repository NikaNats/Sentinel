using System.Globalization;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Sentinel.Infrastructure.Auth;
using Sentinel.Security.Abstractions.Exceptions;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Security;
using Sentinel.Security.Abstractions.Session;

namespace Sentinel.Tests.Unit.Auth;

public sealed class TokenValidationServiceTests
{
    private readonly FakeTimeProvider _timeProvider;
    private readonly Mock<IJtiReplayCache> _replayCacheMock;
    private readonly Mock<ISessionBlacklistCache> _sessionBlacklistMock;
    private readonly Mock<ISecurityEventEmitter> _eventEmitterMock;
    private readonly TokenValidationService _sut;

    public TokenValidationServiceTests()
    {
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        _replayCacheMock = new Mock<IJtiReplayCache>(MockBehavior.Strict);
        _sessionBlacklistMock = new Mock<ISessionBlacklistCache>(MockBehavior.Strict);
        _eventEmitterMock = new Mock<ISecurityEventEmitter>(MockBehavior.Strict);

        _sut = new TokenValidationService(
            _replayCacheMock.Object,
            _sessionBlacklistMock.Object,
            _eventEmitterMock.Object,
            _timeProvider);
    }

    [Fact]
    public async Task ValidateAsync_WhenNowEqualsExpiry_ReturnsFailure_AndSkipsSideEffects()
    {
        var now = _timeProvider.GetUtcNow();
        var principal = BuildPrincipal(
            ("jti", "jti-boundary-123"),
            ("sub", "user-001"),
            ("exp", now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));

        var result = await _sut.ValidateAsync(principal, new DefaultHttpContext(), CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.FailureReason.Should().Be("Token is already expired.");
        result.FailureException.Should().BeNull();

        _replayCacheMock.VerifyNoOtherCalls();
        _sessionBlacklistMock.VerifyNoOtherCalls();
        _eventEmitterMock.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task ValidateAsync_WhenJtiAlreadyUsed_ReturnsReplayFailureAndEmitsEvent()
    {
        var futureExp = _timeProvider.GetUtcNow().AddMinutes(5);
        const string jti = "jti-replay-attack";
        const string sub = "attacker-001";

        var principal = BuildPrincipal(
            ("jti", jti),
            ("sub", sub),
            ("exp", futureExp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));

        _replayCacheMock
            .Setup(x => x.TryMarkUsedAsync(jti, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        _eventEmitterMock
            .Setup(x => x.EmitTokenReplay(jti, sub, It.IsAny<string>(), It.IsAny<string>()));

        var result = await _sut.ValidateAsync(principal, new DefaultHttpContext(), CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.FailureReason.Should().Be("Token replay detected.");
        result.FailureException.Should().BeNull();

        _eventEmitterMock.Verify(x => x.EmitTokenReplay(jti, sub, It.IsAny<string>(), It.IsAny<string>()), Times.Once);
        _replayCacheMock.Verify(x => x.TryMarkUsedAsync(jti, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.Once);
        _sessionBlacklistMock.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task ValidateAsync_WhenSessionBlacklisted_ReturnsSessionFailure()
    {
        var futureExp = _timeProvider.GetUtcNow().AddMinutes(5);
        const string jti = "jti-valid";
        const string sid = "sid-revoked";

        var principal = BuildPrincipal(
            ("jti", jti),
            ("sub", "user-revoked"),
            ("sid", sid),
            ("exp", futureExp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));

        _replayCacheMock
            .Setup(x => x.TryMarkUsedAsync(jti, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        _sessionBlacklistMock
            .Setup(x => x.IsBlacklistedAsync(sid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var result = await _sut.ValidateAsync(principal, new DefaultHttpContext(), CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.FailureReason.Should().Be("Session has been terminated.");
        result.FailureException.Should().BeNull();

        _replayCacheMock.Verify(x => x.TryMarkUsedAsync(jti, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.Once);
        _sessionBlacklistMock.Verify(x => x.IsBlacklistedAsync(sid, It.IsAny<CancellationToken>()), Times.Once);
        _eventEmitterMock.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task ValidateAsync_WhenReplayCacheUnavailable_ReturnsExceptionOutcome()
    {
        var replayError = new ReplayCacheUnavailableException("Redis cluster unreachable");
        var futureExp = _timeProvider.GetUtcNow().AddMinutes(5);

        var principal = BuildPrincipal(
            ("jti", "jti-cache-fail"),
            ("sub", "user-001"),
            ("exp", futureExp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));

        _replayCacheMock
            .Setup(x => x.TryMarkUsedAsync("jti-cache-fail", It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(replayError);

        var result = await _sut.ValidateAsync(principal, new DefaultHttpContext(), CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.FailureReason.Should().BeNull();
        result.FailureException.Should().Be(replayError);

        _sessionBlacklistMock.VerifyNoOtherCalls();
        _eventEmitterMock.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task ValidateAsync_WhenClaimsAndStateAreValid_ReturnsSuccess()
    {
        var futureExp = _timeProvider.GetUtcNow().AddMinutes(5);
        const string jti = "jti-valid-001";
        const string sid = "sid-active";

        var principal = BuildPrincipal(
            ("jti", jti),
            ("sub", "user-authenticated"),
            ("sid", sid),
            ("exp", futureExp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));

        _replayCacheMock
            .Setup(x => x.TryMarkUsedAsync(jti, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        _sessionBlacklistMock
            .Setup(x => x.IsBlacklistedAsync(sid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var result = await _sut.ValidateAsync(principal, new DefaultHttpContext(), CancellationToken.None);

        result.IsSuccess.Should().BeTrue();
        result.FailureReason.Should().BeNull();
        result.FailureException.Should().BeNull();

        _eventEmitterMock.VerifyNoOtherCalls();
    }

    private static ClaimsPrincipal BuildPrincipal(params (string Type, string Value)[] claims)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(claims.Select(x => new Claim(x.Type, x.Value)), "test"));
    }
}
