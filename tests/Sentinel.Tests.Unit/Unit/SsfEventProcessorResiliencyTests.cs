using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Security.Abstractions.Security;
using Sentinel.Security.Abstractions.Session;
using Sentinel.Security.Abstractions.SSF;
using Sentinel.SSF;

namespace Sentinel.Tests.Unit.Ssf;

public sealed class SsfEventProcessorResiliencyTests
{
    private const string SessionRevokedEventType =
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

    private const string CredentialChangeEventType =
        "https://schemas.openid.net/secevent/caep/event-type/credential-change";

    private static SsfEventProcessor CreateSut(
        ISsfTokenValidator validator,
        ISessionBlacklistCache blacklist,
        IAuthRevocationService revocation,
        TimeProvider? timeProvider = null)
    {
        var options = Microsoft.Extensions.Options.Options.Create(new SsfProcessingOptions
        {
            SessionRevocationTtlSeconds = 3600,
            MaxEventAgeSeconds = 300,
            AllowedClockSkewSeconds = 300
        });

        return new SsfEventProcessor(
            validator,
            blacklist,
            revocation,
            options,
            NullLogger<SsfEventProcessor>.Instance,
            timeProvider ?? TimeProvider.System);
    }

    [Fact]
    public async Task ProcessAsync_WhenTokenValidationFails_ReturnsFailure()
    {
        var validatorMock = new Mock<ISsfTokenValidator>();
        var blacklistMock = new Mock<ISessionBlacklistCache>();
        var revocationMock = new Mock<IAuthRevocationService>();

        validatorMock
            .Setup(x => x.ValidateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SsfValidationResult.Fail("Invalid signature"));

        var sut = CreateSut(validatorMock.Object, blacklistMock.Object, revocationMock.Object);

        var result = await sut.ProcessAsync("invalid-set-token");

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Contain("Invalid signature");
    }

    [Fact]
    public async Task ProcessAsync_WhenOneEventFails_ReturnsFailureAndContinuesProcessing()
    {
        var validatorMock = new Mock<ISsfTokenValidator>();
        var blacklistMock = new Mock<ISessionBlacklistCache>();
        var revocationMock = new Mock<IAuthRevocationService>();

        blacklistMock
            .Setup(x => x.BlacklistSessionAsync("sid-1", It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Database offline"));

        revocationMock
            .Setup(x => x.RevokeAllSessionsAsync("user-2", It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var events = new Dictionary<string, JsonElement>
        {
            [SessionRevokedEventType] = JsonSerializer.SerializeToElement(new SessionRevokedPayload("sid-1", null)),
            [CredentialChangeEventType] = JsonSerializer.SerializeToElement(new CredentialChangePayload("user-2"))
        };

        var token = new SsfEventToken(
            "iss",
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            "jti-1",
            "aud",
            "sub",
            events);

        validatorMock
            .Setup(x => x.ValidateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SsfValidationResult.Success(token));

        var sut = CreateSut(validatorMock.Object, blacklistMock.Object, revocationMock.Object);

        var result = await sut.ProcessAsync("valid-set-token");

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().NotBeNull();
        result.ErrorMessage!.ToLowerInvariant().Should().Contain("failed to process");
        blacklistMock.Verify(
            x => x.BlacklistSessionAsync("sid-1", It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.Once);
        revocationMock.Verify(x => x.RevokeAllSessionsAsync("user-2", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ProcessAsync_WhenAllEventsSucceed_ReturnsSuccess()
    {
        var validatorMock = new Mock<ISsfTokenValidator>();
        var blacklistMock = new Mock<ISessionBlacklistCache>();
        var revocationMock = new Mock<IAuthRevocationService>();

        blacklistMock
            .Setup(x => x.BlacklistSessionAsync("sid-2", It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var events = new Dictionary<string, JsonElement>
        {
            [SessionRevokedEventType] = JsonSerializer.SerializeToElement(new SessionRevokedPayload("sid-2", null))
        };

        var token = new SsfEventToken(
            "iss",
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            "jti-2",
            "aud",
            "sub",
            events);

        validatorMock
            .Setup(x => x.ValidateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SsfValidationResult.Success(token));

        var sut = CreateSut(validatorMock.Object, blacklistMock.Object, revocationMock.Object);

        var result = await sut.ProcessAsync("valid-set-token");

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task ProcessAsync_WhenSetTokenIsEmpty_ReturnsFailure()
    {
        var validatorMock = new Mock<ISsfTokenValidator>();
        var blacklistMock = new Mock<ISessionBlacklistCache>();
        var revocationMock = new Mock<IAuthRevocationService>();

        var sut = CreateSut(validatorMock.Object, blacklistMock.Object, revocationMock.Object);

        var result = await sut.ProcessAsync(string.Empty);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().NotBeNull();
        result.ErrorMessage!.ToLowerInvariant().Should().Contain("required");
    }
}
