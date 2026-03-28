using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.RAR;

namespace Sentinel.Tests.Unit;

public sealed class RarExtractorTests
{
    private static RarExtractor CreateSut(int maxCount = 100)
    {
        var options = Microsoft.Extensions.Options.Options.Create(new RarValidationOptions
            { MaxAuthorizationDetailsCount = maxCount });
        return new RarExtractor(options, NullLogger<RarExtractor>.Instance);
    }

    [Fact]
    public void Extract_WhenJsonIsEmpty_ReturnsEmptyArray()
    {
        var sut = CreateSut();
        var result = sut.Extract("");

        result.IsValid.Should().BeTrue();
        result.Details.Should().NotBeNull();
        result.Details.Should().BeEmpty();
    }

    [Fact]
    public void Extract_WhenJsonIsMalformed_ReturnsFailure()
    {
        var sut = CreateSut();
        var result = sut.Extract("[{bad-json]");

        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Extract_WhenDetailsExceedMaxCount_ReturnsFailure()
    {
        var sut = CreateSut(1);
        var result = sut.Extract("[{\"type\":\"urn:test:one\"},{\"type\":\"urn:test:two\"}]");

        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Extract_WhenJsonHasValidArray_ReturnsSuccess()
    {
        var sut = CreateSut();
        var result =
            sut.Extract(
                "[{\"type\":\"urn:test:payment\",\"transaction_id\":\"txn-1\",\"amount\":10.0,\"currency\":\"USD\"}]");

        result.IsValid.Should().BeTrue();
        result.Details.Should().NotBeNull();
        result.Details.Should().HaveCount(1);
    }
}
