using Microsoft.Extensions.Logging;
using Moq;
using Sentinel.Security.Diagnostics;

namespace Sentinel.Tests.Unit.Unit;

public sealed class SecurityEventEmitterTests
{
    [Fact(DisplayName = "🛡️ SIEM/Audit: Session revocation MUST hash both sessionId and sub before logging")]
    public void EmitSessionRevoked_HashesIdentifiers_BeforeLogging()
    {
        var loggerMock = new Mock<ILogger<SecurityEventEmitter>>();
        var hasherMock = new Mock<IPrivacyPreservingHasher>(MockBehavior.Strict);

        const string rawSessionId = "session-id-123456789";
        const string rawSub = "user-uuid-987654321";

        hasherMock.Setup(h => h.Hash(rawSessionId)).Returns("hashed-session-id");
        hasherMock.Setup(h => h.Hash(rawSub)).Returns("hashed-user-sub");

        var sut = new SecurityEventEmitter(loggerMock.Object, hasherMock.Object);

        sut.EmitSessionRevoked(rawSessionId, rawSub);

        hasherMock.Verify(h => h.Hash(rawSessionId), Times.Once);
        hasherMock.Verify(h => h.Hash(rawSub), Times.Once);
    }

    [Fact(DisplayName = "🛡️ SIEM/Audit: Token replay alert MUST hash jti, sub, and clientId before logging")]
    public void EmitTokenReplay_HashesIdentifiers_BeforeLogging()
    {
        var loggerMock = new Mock<ILogger<SecurityEventEmitter>>();
        var hasherMock = new Mock<IPrivacyPreservingHasher>(MockBehavior.Strict);

        const string rawJti = "jti-token-unique-val";
        const string rawSub = "user-subject-id";
        const string rawClientId = "sentinel-portal-client";

        hasherMock.Setup(h => h.Hash(rawJti)).Returns("hashed-jti");
        hasherMock.Setup(h => h.Hash(rawSub)).Returns("hashed-sub");
        hasherMock.Setup(h => h.Hash(rawClientId)).Returns("hashed-client-id");

        var sut = new SecurityEventEmitter(loggerMock.Object, hasherMock.Object);

        sut.EmitTokenReplay(rawJti, rawSub, rawClientId, "ip-hash-value-abc");

        hasherMock.Verify(h => h.Hash(rawJti), Times.Once);
        hasherMock.Verify(h => h.Hash(rawSub), Times.Once);
        hasherMock.Verify(h => h.Hash(rawClientId), Times.Once);
    }

    [Fact(DisplayName = "🛡️ SIEM/Audit: DPoP validation failure MUST hash thumbprint before logging")]
    public void EmitDpopValidationFailure_HashesThumbprint_BeforeLogging()
    {
        var loggerMock = new Mock<ILogger<SecurityEventEmitter>>();
        var hasherMock = new Mock<IPrivacyPreservingHasher>(MockBehavior.Strict);

        const string rawThumbprint = "dpop-public-key-thumbprint-xyz";

        hasherMock.Setup(h => h.Hash(rawThumbprint)).Returns("hashed-thumbprint");

        var sut = new SecurityEventEmitter(loggerMock.Object, hasherMock.Object);

        sut.EmitDpopValidationFailure(rawThumbprint, "invalid_signature", "ip-hash-value-abc");

        hasherMock.Verify(h => h.Hash(rawThumbprint), Times.Once);
    }
}
