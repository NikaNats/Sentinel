using Sentinel.RAR;
using FluentAssertions;

namespace Sentinel.Tests.Unit;

public sealed class RarExtractorTests
{
    private readonly RarExtractor _sut = new();

    [Fact]
    public void Extract_WhenJsonIsEmpty_ReturnsEmptyArray()
    {
        // Act
        var result = _sut.Extract("");

        // Assert
        result.IsValid.Should().BeTrue();
        result.Details.Should().BeEmpty();
    }

    [Fact]
    public void Extract_WhenJsonIsWhitespace_ReturnsEmptyArray()
    {
        // Act
        var result = _sut.Extract("   ");

        // Assert
        result.IsValid.Should().BeTrue();
        result.Details.Should().BeEmpty();
    }

    [Fact]
    public void Extract_WhenJsonIsNull_ReturnsEmpty()
    {
        // Act
        var result = _sut.Extract(null ?? "");

        // Assert
        result.IsValid.Should().BeTrue();
        result.Details.Should().BeEmpty();
    }

    [Fact]
    public void Extract_WhenJsonIsNotArray_ReturnsFailure()
    {
        // Act
        var result = _sut.Extract("{\"type\":\"urn:test\"}");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().Contain("array", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Extract_WhenDetailsExceedMaxCount_ReturnsFailure()
    {
        // Arrange
        var sut = new RarExtractor(new RarValidationOptions { MaxAuthorizationDetailsCount = 1 });
        var json = "[{\"type\":\"t1\"}, {\"type\":\"t2\"}]";

        // Act
        var result = sut.Extract(json);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().Contain("exceeds", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Extract_WhenJsonIsMalformed_ReturnsFailure()
    {
        // Act
        var result = _sut.Extract("[{bad-json]");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Extract_WhenJsonHasValidArray_ReturnsSuccess()
    {
        // Arrange
        var json = "[]";

        // Act
        var result = _sut.Extract(json);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Details.Should().NotBeNull();
    }

    [Fact]
    public void Extract_WithCustomMaxCount_EnforcesLimit()
    {
        // Arrange
        var sut = new RarExtractor(new RarValidationOptions { MaxAuthorizationDetailsCount = 2 });
        var json = "[{\"type\":\"t1\"}, {\"type\":\"t2\"}, {\"type\":\"t3\"}]";

        // Act
        var result = sut.Extract(json);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Extract_AtExactMaxCount_Succeeds()
    {
        // Arrange
        var sut = new RarExtractor(new RarValidationOptions { MaxAuthorizationDetailsCount = 2 });
        var json = "[{\"type\":\"t1\"}, {\"type\":\"t2\"}]";

        // Act
        var result = sut.Extract(json);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Extract_WithEmptyArrayObject_Succeeds()
    {
        // Arrange
        var json = "[{}]";

        // Act
        var result = _sut.Extract(json);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Extract_WithVeryLargeJson_ReturnsFailureIfExceedsMaxCount()
    {
        // Arrange
        var sut = new RarExtractor(new RarValidationOptions { MaxAuthorizationDetailsCount = 1 });
        var json = string.Create(10000, 0, (span, _) =>
        {
            var content = "[{\"type\":\"t1\"}, {\"type\":\"t2\"}]";
            content.AsSpan().CopyTo(span);
        });

        // Act
        var result = sut.Extract(json);

        // Assert
        result.IsValid.Should().BeFalse();
    }
}
