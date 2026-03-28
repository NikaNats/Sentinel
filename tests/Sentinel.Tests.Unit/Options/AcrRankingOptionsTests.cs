using FluentAssertions;
using Sentinel.Security.Abstractions.Options;

namespace Sentinel.Tests.Unit.Options;

public sealed class AcrRankingOptionsTests
{
    [Fact]
    public void Validate_WhenRankingsAreEmpty_ThrowsInvalidOperationException()
    {
        var options = new AcrRankingOptions { Rankings = new Dictionary<string, int>() };

        var act = () => options.Validate();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*cannot be empty*");
    }

    [Fact]
    public void Validate_WhenRankingsHaveDuplicateValues_ThrowsInvalidOperationException()
    {
        var options = new AcrRankingOptions
        {
            Rankings = new Dictionary<string, int>
            {
                ["acr1"] = 1,
                ["acr2"] = 1 // Duplicate rank value!
            }
        };

        var act = () => options.Validate();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*duplicate ranks*");
    }

    [Fact]
    public void Validate_WhenRankingsAreValid_DoesNotThrow()
    {
        var options = new AcrRankingOptions
        {
            Rankings = new Dictionary<string, int>
            {
                ["acr1"] = 1,
                ["acr2"] = 2
            }
        };

        var act = () => options.Validate();

        act.Should().NotThrow();
    }
}
