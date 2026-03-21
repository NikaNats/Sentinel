using System.Security.Claims;
using System.Globalization;
using Microsoft.AspNetCore.Http;
using Moq;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Auth;

namespace Sentinel.Tests.Unit;

public sealed class TokenValidationServiceTests
{
    [Fact]
    public async Task ValidateAsync_WhenJtiAlreadyUsed_ReturnsReplayFailureAndEmitsEvent()
    {
        var replayCache = new Mock<IJtiReplayCache>();
        replayCache
            .Setup(x => x.TryStoreIfNotExistsAsync("jti-1", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var sessionBlacklist = new Mock<ISessionBlacklistCache>();
        var emitter = new Mock<ISecurityEventEmitter>();

        var sut = new TokenValidationService(replayCache.Object, sessionBlacklist.Object, emitter.Object);
        var principal = BuildPrincipal(("jti", "jti-1"), ("exp", DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)), ("sub", "user-1"));
        var context = new DefaultHttpContext();

        var result = await sut.ValidateAsync(principal, context, CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal("Token replay detected.", result.FailureReason);
        emitter.Verify(x => x.EmitTokenReplay("jti-1", "user-1", "sentinel-api-client", It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ValidateAsync_WhenSessionIsBlacklisted_ReturnsSessionFailureAndEmitsEvent()
    {
        var replayCache = new Mock<IJtiReplayCache>();
        replayCache
            .Setup(x => x.TryStoreIfNotExistsAsync("jti-1", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var sessionBlacklist = new Mock<ISessionBlacklistCache>();
        sessionBlacklist
            .Setup(x => x.IsSessionBlacklistedAsync("sid-1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var emitter = new Mock<ISecurityEventEmitter>();
        var sut = new TokenValidationService(replayCache.Object, sessionBlacklist.Object, emitter.Object);
        var principal = BuildPrincipal(("jti", "jti-1"), ("exp", DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)), ("sub", "user-1"), ("sid", "sid-1"));
        var context = new DefaultHttpContext();

        var result = await sut.ValidateAsync(principal, context, CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal("Session has been terminated.", result.FailureReason);
        emitter.Verify(x => x.EmitAuthFailure("revoked_session_usage_attempt", "user-1", It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ValidateAsync_WhenReplayCacheUnavailable_ReturnsExceptionOutcomeAndEmitsEvent()
    {
        var replayUnavailable = new ReplayCacheUnavailableException("cache unavailable", new InvalidOperationException("redis offline"));
        var replayCache = new Mock<IJtiReplayCache>();
        replayCache
            .Setup(x => x.TryStoreIfNotExistsAsync("jti-1", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(replayUnavailable);

        var sessionBlacklist = new Mock<ISessionBlacklistCache>();
        var emitter = new Mock<ISecurityEventEmitter>();
        var sut = new TokenValidationService(replayCache.Object, sessionBlacklist.Object, emitter.Object);
        var principal = BuildPrincipal(("jti", "jti-1"), ("exp", DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)), ("sub", "user-1"));
        var context = new DefaultHttpContext();

        var result = await sut.ValidateAsync(principal, context, CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Same(replayUnavailable, result.FailureException);
        emitter.Verify(x => x.EmitAuthFailure("replay_cache_unavailable", "user-1", It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ValidateAsync_WhenClaimsAndStateAreValid_ReturnsSuccess()
    {
        var replayCache = new Mock<IJtiReplayCache>();
        replayCache
            .Setup(x => x.TryStoreIfNotExistsAsync("jti-1", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var sessionBlacklist = new Mock<ISessionBlacklistCache>();
        sessionBlacklist
            .Setup(x => x.IsSessionBlacklistedAsync("sid-1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var emitter = new Mock<ISecurityEventEmitter>();
        var sut = new TokenValidationService(replayCache.Object, sessionBlacklist.Object, emitter.Object);
        var principal = BuildPrincipal(("jti", "jti-1"), ("exp", DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)), ("sub", "user-1"), ("sid", "sid-1"));
        var context = new DefaultHttpContext();

        var result = await sut.ValidateAsync(principal, context, CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Null(result.FailureReason);
        Assert.Null(result.FailureException);
        emitter.VerifyNoOtherCalls();
    }

    private static ClaimsPrincipal BuildPrincipal(params (string Type, string Value)[] claims)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(claims.Select(x => new Claim(x.Type, x.Value)), "test"));
    }
}
