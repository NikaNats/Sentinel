using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.DPoP;
using Sentinel.RAR;
using Sentinel.Security.Abstractions.Replay;

namespace Sentinel.Tests.Security;

public sealed class HandlerRobustnessEdgeCaseTests
{
    [Fact]
    public void RarExtractor_WhenOptionsAreNull_ThrowsArgumentNullException()
    {
        var act = () => new RarExtractor(null!, NullLogger<RarExtractor>.Instance);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void FinancialAuthorizationMatcher_WhenLoggerIsNull_ThrowsArgumentNullException()
    {
        var options = Options.Create(new RarValidationOptions());
        var act = () => new FinancialAuthorizationMatcher(options, null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void DpopProofValidator_WhenOptionsAreNull_ThrowsArgumentNullException()
    {
        var replayCache = Mock.Of<IJtiReplayCache>();

        var act = () => new DpopProofValidator(replayCache, null!);

        act.Should().Throw<ArgumentNullException>();
    }
}
