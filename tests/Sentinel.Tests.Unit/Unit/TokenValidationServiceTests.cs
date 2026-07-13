using System.Globalization;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Sentinel.Infrastructure.Auth;
using Sentinel.Security.Abstractions.Exceptions;
using Sentinel.Security.Abstractions.Session;

namespace Sentinel.Tests.Unit.Unit;

public sealed class TokenValidationServiceTests
{
    private readonly Mock<ISessionBlacklistCache> _sessionBlacklistMock;
    private readonly TokenValidationService _sut;
    private readonly FakeTimeProvider _timeProvider;

    public TokenValidationServiceTests()
    {
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        _sessionBlacklistMock = new Mock<ISessionBlacklistCache>(MockBehavior.Strict);

        _sut = new TokenValidationService(
            _sessionBlacklistMock.Object,
            NullLogger<TokenValidationService>.Instance,
            _timeProvider);
    }

    [Fact(DisplayName = "⏱️ Temporal Boundary: Token is rejected exactly at expiry time")]
    public async Task ValidateAsync_WhenNowEqualsExpiry_ReturnsFailure()
    {
        var now = _timeProvider.GetUtcNow();
        var principal = BuildPrincipal(
            ("sub", "user-001"),
            ("exp", now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));

        var result = await _sut.ValidateAsync(principal, new DefaultHttpContext(), CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.FailureReason.Should().Be("Token is already expired.");
        result.FailureException.Should().BeNull();

        _sessionBlacklistMock.VerifyNoOtherCalls();
    }

    [Fact(DisplayName = "🔐 Session Blacklist: Terminated session MUST result in rejection")]
    public async Task ValidateAsync_WhenSessionBlacklisted_ReturnsSessionFailure()
    {
        var futureExp = _timeProvider.GetUtcNow().AddMinutes(5);
        const string sub = "user-revoked";
        const string sid = "sid-revoked";

        var principal = BuildPrincipal(
            ("sub", sub),
            ("sid", sid),
            ("exp", futureExp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));

        _sessionBlacklistMock
            .Setup(x => x.IsBlacklistedAsync(sub, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        _sessionBlacklistMock
            .Setup(x => x.IsBlacklistedAsync(sid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var result = await _sut.ValidateAsync(principal, new DefaultHttpContext(), CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.FailureReason.Should().Be("Session has been terminated.");
        result.FailureException.Should().BeNull();

        _sessionBlacklistMock.Verify(x => x.IsBlacklistedAsync(sub, It.IsAny<CancellationToken>()), Times.Once);
        _sessionBlacklistMock.Verify(x => x.IsBlacklistedAsync(sid, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact(DisplayName = "🔐 Subject Blacklist: Globally revoked user MUST result in fail-fast rejection")]
    public async Task ValidateAsync_WhenSubjectBlacklisted_ReturnsSubjectFailure()
    {
        var futureExp = _timeProvider.GetUtcNow().AddMinutes(5);
        const string sub = "user-globally-blocked";
        const string sid = "sid-active";

        var principal = BuildPrincipal(
            ("sub", sub),
            ("sid", sid),
            ("exp", futureExp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));

        _sessionBlacklistMock
            .Setup(x => x.IsBlacklistedAsync(sub, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        _sessionBlacklistMock
            .Setup(x => x.IsBlacklistedAsync(sid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var result = await _sut.ValidateAsync(principal, new DefaultHttpContext(), CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.FailureReason.Should().Be("User account has been globally revoked or locked.");
        result.FailureException.Should().BeNull();

        _sessionBlacklistMock.Verify(x => x.IsBlacklistedAsync(sub, It.IsAny<CancellationToken>()), Times.Once);
        _sessionBlacklistMock.Verify(x => x.IsBlacklistedAsync(sid, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact(DisplayName = "⚠️ Fail-Closed: Cache outage during check throws and returns exception")]
    public async Task ValidateAsync_WhenSessionBlacklistUnavailable_ReturnsExceptionOutcome()
    {
        var blacklistError = new SessionBlacklistUnavailableException("Redis cluster unreachable");
        var futureExp = _timeProvider.GetUtcNow().AddMinutes(5);
        const string sub = "user-001";
        const string sid = "sid-unavailable";

        var principal = BuildPrincipal(
            ("sub", sub),
            ("sid", sid),
            ("exp", futureExp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));

        _sessionBlacklistMock
            .Setup(x => x.IsBlacklistedAsync(sub, It.IsAny<CancellationToken>()))
            .ThrowsAsync(blacklistError);

        _sessionBlacklistMock
            .Setup(x => x.IsBlacklistedAsync(sid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var result = await _sut.ValidateAsync(principal, new DefaultHttpContext(), CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.FailureReason.Should().BeNull();
        result.FailureException.Should().Be(blacklistError);
    }

    [Fact(DisplayName = "✓ Happy Path: Unexpired token with active session returns Success")]
    public async Task ValidateAsync_WhenClaimsAndStateAreValid_ReturnsSuccess()
    {
        var futureExp = _timeProvider.GetUtcNow().AddMinutes(5);
        const string sub = "user-authenticated";
        const string sid = "sid-active";

        var principal = BuildPrincipal(
            ("sub", sub),
            ("sid", sid),
            ("exp", futureExp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));

        _sessionBlacklistMock
            .Setup(x => x.IsBlacklistedAsync(sub, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        _sessionBlacklistMock
            .Setup(x => x.IsBlacklistedAsync(sid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var result = await _sut.ValidateAsync(principal, new DefaultHttpContext(), CancellationToken.None);

        result.IsSuccess.Should().BeTrue();
        result.FailureReason.Should().BeNull();
        result.FailureException.Should().BeNull();

        _sessionBlacklistMock.Verify(x => x.IsBlacklistedAsync(sub, It.IsAny<CancellationToken>()), Times.Once);
        _sessionBlacklistMock.Verify(x => x.IsBlacklistedAsync(sid, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact(DisplayName = "✓ M2M Flow: Valid token without session (no 'sid') returns Success")]
    public async Task ValidateAsync_WhenSessionMissing_ReturnsSuccess()
    {
        var futureExp = _timeProvider.GetUtcNow().AddMinutes(5);
        const string sub = "m2m-client";

        var principal = BuildPrincipal(
            ("sub", sub),
            ("exp", futureExp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));

        _sessionBlacklistMock
            .Setup(x => x.IsBlacklistedAsync(sub, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var result = await _sut.ValidateAsync(principal, new DefaultHttpContext(), CancellationToken.None);

        result.IsSuccess.Should().BeTrue();
        result.FailureReason.Should().BeNull();
        result.FailureException.Should().BeNull();

        _sessionBlacklistMock.Verify(x => x.IsBlacklistedAsync(sub, It.IsAny<CancellationToken>()), Times.Once);
    }

    private static ClaimsPrincipal BuildPrincipal(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(x => new Claim(x.Type, x.Value)), "test"));
}
