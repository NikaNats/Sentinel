using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Auth.Ssf;

namespace Sentinel.Tests.Unit;

public sealed class SsfEventProcessorTests
{
    [Fact]
    public async Task ProcessAsync_WhenSessionRevoked_BlacklistsSid()
    {
        var sid = "sid-123";
        var token = new SecurityEventToken(
            "https://issuer.local",
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            "jti-1",
            "sentinel-api",
            "user-1",
            new Dictionary<string, JsonElement>
            {
                ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"] =
                    JsonSerializer.SerializeToElement(new SessionRevokedPayload(sid, "user-1"))
            });

        var validator = new Mock<ISsfTokenValidator>();
        validator.Setup(x => x.ValidateAsync("set-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(SsfValidationResult.Success(token));

        var blacklist = new Mock<ISessionBlacklistCache>();
        var revocation = new Mock<IAuthRevocationService>();
        var sut = new SsfEventProcessor(
            validator.Object,
            blacklist.Object,
            revocation.Object,
            Options.Create(new SsfOptions { SessionRevocationTtlSeconds = 1800 }),
            NullLogger<SsfEventProcessor>.Instance);

        var result = await sut.ProcessAsync("set-token", CancellationToken.None);

        Assert.True(result.IsSuccess);
        blacklist.Verify(
            x => x.BlacklistSessionAsync("sid-123", TimeSpan.FromSeconds(1800), It.IsAny<CancellationToken>()),
            Times.Once);
        revocation.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task ProcessAsync_WhenUserStatusChanged_RevokesAllSessions()
    {
        var token = new SecurityEventToken(
            "https://issuer.local",
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            "jti-2",
            "sentinel-api",
            "user-2",
            new Dictionary<string, JsonElement>
            {
                ["https://schemas.openid.net/secevent/caep/event-type/user-status-changed"] =
                    JsonSerializer.SerializeToElement(new UserStatusChangedPayload("user-2"))
            });

        var validator = new Mock<ISsfTokenValidator>();
        validator.Setup(x => x.ValidateAsync("set-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(SsfValidationResult.Success(token));

        var blacklist = new Mock<ISessionBlacklistCache>();
        var revocation = new Mock<IAuthRevocationService>();
        revocation.Setup(x => x.RevokeAllSessionsAsync("user-2", It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var sut = new SsfEventProcessor(
            validator.Object,
            blacklist.Object,
            revocation.Object,
            Options.Create(new SsfOptions()),
            NullLogger<SsfEventProcessor>.Instance);

        var result = await sut.ProcessAsync("set-token", CancellationToken.None);

        Assert.True(result.IsSuccess);
        revocation.Verify(x => x.RevokeAllSessionsAsync("user-2", It.IsAny<CancellationToken>()), Times.Once);
        blacklist.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task ProcessAsync_WhenValidationFails_ReturnsUnauthorized()
    {
        var validator = new Mock<ISsfTokenValidator>();
        validator.Setup(x => x.ValidateAsync("bad-set", It.IsAny<CancellationToken>()))
            .ReturnsAsync(SsfValidationResult.Fail("invalid signature"));

        var sut = new SsfEventProcessor(
            validator.Object,
            Mock.Of<ISessionBlacklistCache>(),
            Mock.Of<IAuthRevocationService>(),
            Options.Create(new SsfOptions()),
            NullLogger<SsfEventProcessor>.Instance);

        var result = await sut.ProcessAsync("bad-set", CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.True(result.IsUnauthorized);
        Assert.Equal("invalid signature", result.Error);
    }
}
