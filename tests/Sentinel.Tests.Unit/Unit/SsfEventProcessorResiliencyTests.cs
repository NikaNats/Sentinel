using System.Text.Json;
using Moq;
using Sentinel.Security.Abstractions.Session;
using Sentinel.Security.Abstractions.Security;
using Sentinel.Security.Abstractions.SSF;
using Sentinel.SSF;
using FluentAssertions;

namespace Sentinel.Tests.Unit.Ssf;

public sealed class SsfEventProcessorResiliencyTests
{
    private const string SessionRevokedEventType = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    private const string CredentialChangeEventType = "https://schemas.openid.net/secevent/caep/event-type/credential-change";

    [Fact]
    public async Task ProcessAsync_WhenOneEventThrows_ContinuesProcessingRemainingEvents()
    {
        // Arrange: Simulate a SET token with two events.
        // The first one will throw an exception during processing, the second should still succeed.
        var validatorMock = new Mock<ISsfTokenValidator>();
        var blacklistMock = new Mock<ISessionBlacklistCache>();
        var revocationMock = new Mock<IAuthRevocationService>();

        // Make the blacklist cache throw for session-revoked event, but credential-change succeeds
        blacklistMock
            .Setup(x => x.BlacklistSessionAsync("sid-1", It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Database offline"));

        // Create event payloads
        var sessionRevokedPayload = JsonSerializer.SerializeToElement(new { sid = "sid-1" });
        var credentialChangePayload = JsonSerializer.SerializeToElement(new { sub = "user-2" });

        var events = new Dictionary<string, JsonElement>
        {
            [SessionRevokedEventType] = sessionRevokedPayload,
            [CredentialChangeEventType] = credentialChangePayload
        };

        var token = new SsfEventToken("iss", 1234567890, "jti", "aud", "sub", events);
        validatorMock.Setup(x => x.ValidateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                     .ReturnsAsync(SsfValidationResult.Success(token));

        var sut = new SsfEventProcessor(validatorMock.Object, blacklistMock.Object, revocationMock.Object);

        // Act
        var result = await sut.ProcessAsync("valid-set-token");

        // Assert
        result.IsSuccess.Should().BeTrue("Overall batch should succeed despite individual event failures");
        blacklistMock.Verify(
            x => x.BlacklistSessionAsync("sid-1", It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.Once,
            "Session-revoked event processing should be attempted");

        revocationMock.Verify(
            x => x.RevokeAllSessionsAsync("user-2", It.IsAny<CancellationToken>()),
            Times.Once,
            "Credential-change event processing should succeed (PROVES loop continued after exception)");
    }

    [Fact]
    public async Task ProcessAsync_WhenJsonDeserializationFails_ContinuesWithNextEvent()
    {
        // Arrange: Send malformed JSON that can't be deserialized
        var validatorMock = new Mock<ISsfTokenValidator>();
        var blacklistMock = new Mock<ISessionBlacklistCache>();
        var revocationMock = new Mock<IAuthRevocationService>();

        // Malformed payload (missing required fields)
        var sessionRevokedPayload = JsonSerializer.SerializeToElement("{\"invalid\":\"structure\"}");
        var credentialChangePayload = JsonSerializer.SerializeToElement(new { sub = "user-ok" });

        var events = new Dictionary<string, JsonElement>
        {
            [SessionRevokedEventType] = sessionRevokedPayload,
            [CredentialChangeEventType] = credentialChangePayload
        };

        var token = new SsfEventToken("iss", 1234567890, "jti", "aud", "sub", events);
        validatorMock.Setup(x => x.ValidateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                     .ReturnsAsync(SsfValidationResult.Success(token));

        var sut = new SsfEventProcessor(validatorMock.Object, blacklistMock.Object, revocationMock.Object);

        // Act
        var result = await sut.ProcessAsync("valid-set-token");

        // Assert
        result.IsSuccess.Should().BeTrue("Batch succeeds despite malformed event");
        revocationMock.Verify(
            x => x.RevokeAllSessionsAsync("user-ok", It.IsAny<CancellationToken>()),
            Times.Once,
            "Next event should be processed successfully after malformed JSON");
    }

    [Fact]
    public async Task ProcessAsync_WhenTokenValidationFails_ReturnsFailed()
    {
        // Arrange
        var validatorMock = new Mock<ISsfTokenValidator>();
        var blacklistMock = new Mock<ISessionBlacklistCache>();
        var revocationMock = new Mock<IAuthRevocationService>();

        validatorMock.Setup(x => x.ValidateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                     .ReturnsAsync(SsfValidationResult.Failure("Invalid signature"));

        var sut = new SsfEventProcessor(validatorMock.Object, blacklistMock.Object, revocationMock.Object);

        // Act
        var result = await sut.ProcessAsync("invalid-set-token");

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Contain("Invalid signature");
        blacklistMock.Verify(x => x.BlacklistSessionAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ProcessAsync_WhenSetTokenIsNull_ReturnsFailed()
    {
        // Arrange
        var validatorMock = new Mock<ISsfTokenValidator>();
        var blacklistMock = new Mock<ISessionBlacklistCache>();
        var revocationMock = new Mock<IAuthRevocationService>();

        var sut = new SsfEventProcessor(validatorMock.Object, blacklistMock.Object, revocationMock.Object);

        // Act
        var result = await sut.ProcessAsync(null!);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Contain("required", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ProcessAsync_WhenMultipleEventsFail_ContinuesProcessing()
    {
        // Arrange: All events will throw, but processing should continue
        var validatorMock = new Mock<ISsfTokenValidator>();
        var blacklistMock = new Mock<ISessionBlacklistCache>();
        var revocationMock = new Mock<IAuthRevocationService>();

        blacklistMock
            .Setup(x => x.BlacklistSessionAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Cache failed"));

        revocationMock
            .Setup(x => x.RevokeAllSessionsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Service failed"));

        var sessionPayload = JsonSerializer.SerializeToElement(new { sid = "sid-1" });
        var credentialPayload = JsonSerializer.SerializeToElement(new { sub = "user-1" });

        var events = new Dictionary<string, JsonElement>
        {
            [SessionRevokedEventType] = sessionPayload,
            [CredentialChangeEventType] = credentialPayload
        };

        var token = new SsfEventToken("iss", 1234567890, "jti", "aud", "sub", events);
        validatorMock.Setup(x => x.ValidateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                     .ReturnsAsync(SsfValidationResult.Success(token));

        var sut = new SsfEventProcessor(validatorMock.Object, blacklistMock.Object, revocationMock.Object);

        // Act
        var result = await sut.ProcessAsync("valid-set-token");

        // Assert
        result.IsSuccess.Should().BeTrue("Batch succeeds despite all events failing silently");
        blacklistMock.Verify(
            x => x.BlacklistSessionAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.Once);
        revocationMock.Verify(
            x => x.RevokeAllSessionsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Once,
            "Both events attempted despite failures");
    }
}
