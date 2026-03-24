using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.RAR;
using FluentAssertions;

namespace Sentinel.Tests.Unit.Rar;

public sealed class RarValidatorExceptionTests
{
    [Fact]
    public void Validate_WhenPayloadIsMalformedJson_ReturnsFailureCaughtByJsonException()
    {
        // Arrange
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        var sut = new RarValidator(matcherMock.Object, new RarValidationOptions(), NullLogger<RarValidator>.Instance);
        var detail = new AuthorizationDetail("urn:test");

        // Act
        var result = sut.Validate(detail, "{ malformed-json: true ");

        // Assert
        result.IsValid.Should().BeFalse("Malformed JSON should result in validation failure");
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Validate_WhenJsonIsEmpty_ReturnsFailure()
    {
        // Arrange
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        var sut = new RarValidator(matcherMock.Object, new RarValidationOptions(), NullLogger<RarValidator>.Instance);
        var detail = new AuthorizationDetail("urn:test");

        // Act
        var result = sut.Validate(detail, "");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Validate_WhenDetailIsNull_ReturnsFailure()
    {
        // Arrange
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        var sut = new RarValidator(matcherMock.Object, new RarValidationOptions(), NullLogger<RarValidator>.Instance);

        // Act
        var result = sut.Validate(null!, "{}");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Validate_WhenMatcherReturnsNull_ReturnsFailure()
    {
        // Arrange
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        matcherMock.Setup(x => x.Matches(It.IsAny<AuthorizationDetail>(), It.IsAny<JsonElement>()))
                   .Returns(false);

        var sut = new RarValidator(matcherMock.Object, new RarValidationOptions(), NullLogger<RarValidator>.Instance);
        var detail = new AuthorizationDetail("urn:test");

        // Act
        var result = sut.Validate(detail, "{}");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Validate_WhenMatcherThrows_CatchesAndReturnsFailure()
    {
        // Arrange
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        matcherMock.Setup(x => x.Matches(It.IsAny<AuthorizationDetail>(), It.IsAny<JsonElement>()))
                   .Throws(new InvalidOperationException("Matcher error"));

        var sut = new RarValidator(matcherMock.Object, new RarValidationOptions(), NullLogger<RarValidator>.Instance);
        var detail = new AuthorizationDetail("urn:test");

        // Act
        var result = sut.Validate(detail, "{}");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ValidateByType_WhenNoMatchingTypeFound_ReturnsFailure()
    {
        // Arrange
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        var sut = new RarValidator(matcherMock.Object, new RarValidationOptions { CaseSensitiveComparison = true }, NullLogger<RarValidator>.Instance);
        var details = new[] { new AuthorizationDetail("urn:expected:type") };

        // Act
        var result = sut.ValidateByType(details, "urn:different:type", "{}");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ValidateByType_WhenDetailsArrayIsEmpty_ReturnsFailure()
    {
        // Arrange
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        var sut = new RarValidator(matcherMock.Object, new RarValidationOptions(), NullLogger<RarValidator>.Instance);
        var details = Array.Empty<AuthorizationDetail>();

        // Act
        var result = sut.ValidateByType(details, "urn:test", "{}");

        // Assert
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void ValidateByType_WhenPayloadIsInvalidJson_ReturnsFailure()
    {
        // Arrange
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        var sut = new RarValidator(matcherMock.Object, new RarValidationOptions(), NullLogger<RarValidator>.Instance);
        var details = new[] { new AuthorizationDetail("urn:test") };

        // Act
        var result = sut.ValidateByType(details, "urn:test", "{ invalid json");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ValidateByType_WhenMatchingTypeFound_ValidatesSuccessfully()
    {
        // Arrange
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        matcherMock.Setup(x => x.Matches(It.IsAny<AuthorizationDetail>(), It.IsAny<JsonElement>()))
                   .Returns(true);

        var sut = new RarValidator(matcherMock.Object, new RarValidationOptions(), NullLogger<RarValidator>.Instance);
        var detail = new AuthorizationDetail("urn:test");
        var details = new[] { detail };

        // Act
        var result = sut.ValidateByType(details, "urn:test", "{}");

        // Assert
        result.IsValid.Should().BeTrue();
        result.MatchedDetail.Should().Be(detail);
    }

    [Fact]
    public void ValidateByType_WhenCaseSensitiveDisabled_FindsMatchCaseInsensitively()
    {
        // Arrange
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        matcherMock.Setup(x => x.Matches(It.IsAny<AuthorizationDetail>(), It.IsAny<JsonElement>()))
                   .Returns(true);

        var sut = new RarValidator(matcherMock.Object, new RarValidationOptions { CaseSensitiveComparison = false }, NullLogger<RarValidator>.Instance);
        var detail = new AuthorizationDetail("urn:test:type");
        var details = new[] { detail };

        // Act
        var result = sut.ValidateByType(details, "URN:TEST:TYPE", "{}");

        // Assert
        result.IsValid.Should().BeTrue("Case-insensitive comparison should match");
    }

    [Fact]
    public void Validate_WithValidPayloadAndMatchingDetail_ReturnsSuccess()
    {
        // Arrange
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        matcherMock.Setup(x => x.Matches(It.IsAny<AuthorizationDetail>(), It.IsAny<JsonElement>()))
                   .Returns(true);

        var sut = new RarValidator(matcherMock.Object, new RarValidationOptions(), NullLogger<RarValidator>.Instance);
        var detail = new AuthorizationDetail("urn:valid:type");

        // Act
        var result = sut.Validate(detail, "{\"type\":\"urn:valid:type\"}");

        // Assert
        result.IsValid.Should().BeTrue();
        result.MatchedDetail.Should().Be(detail);
    }
}
