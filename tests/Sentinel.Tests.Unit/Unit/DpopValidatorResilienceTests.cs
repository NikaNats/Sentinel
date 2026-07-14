using System.Security.Cryptography;
using FluentAssertions;
using Moq;
using Sentinel.DPoP;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Replay;

namespace Sentinel.Tests.Unit.Unit;

public sealed class DpopValidatorResilienceTests
{
    private readonly Mock<IJtiReplayCache> _replayCacheMock = new();

    public DpopValidatorResilienceTests()
    {
        _replayCacheMock
            .Setup(x => x.TryMarkUsedAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
    }

    [Fact(DisplayName = "🛡️ DPoP Validator: Constructor MUST reject prohibited algorithms (RS256)")]
    public void Constructor_WithProhibitedAlgorithm_ThrowsCryptographicException()
    {
        var options = Microsoft.Extensions.Options.Options.Create(new DPoPOptions
        {
            AllowedAlgorithms = ["RS256", "ES256"]
        });

        var act = () => new DpopProofValidator(_replayCacheMock.Object, options);

        act.Should().Throw<CryptographicException>()
            .WithMessage("*FAPI 2.0 violation*");
    }

    [Fact(DisplayName =
        "🛡️ DPoP Validator: Constructor MUST reject redundant algorithms even if they are strong (e.g. ES512)")]
    public void Constructor_WithRedundantAlgorithms_ThrowsCryptographicException()
    {
        var options = Microsoft.Extensions.Options.Options.Create(new DPoPOptions
        {
            AllowedAlgorithms = ["PS256", "ES256", "ES512"]
        });

        var act = () => new DpopProofValidator(_replayCacheMock.Object, options);

        act.Should().Throw<CryptographicException>()
            .WithMessage("*FAPI 2.0 violation*");
    }

    [Fact(DisplayName = "✅ DPoP Validator: Constructor accepts exactly PS256 and ES256")]
    public void Constructor_WithExactFapiAlgorithms_Succeeds()
    {
        var options = Microsoft.Extensions.Options.Options.Create(new DPoPOptions
        {
            AllowedAlgorithms = ["PS256", "ES256"]
        });

        var act = () => new DpopProofValidator(_replayCacheMock.Object, options);

        act.Should().NotThrow();
    }
}
