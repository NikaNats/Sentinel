using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Domain.Auth.Rar;
using Sentinel.RAR;

namespace Sentinel.Tests.Unit.Unit;

public sealed class RarValidatorExceptionTests
{
    private static RarValidator CreateSut(IAuthorizationDetailMatcher matcher, bool caseSensitive = false)
    {
        var options = Microsoft.Extensions.Options.Options.Create(
            new RarValidationOptions { CaseSensitiveComparison = caseSensitive });
        return new RarValidator([matcher], options, NullLogger<RarValidator>.Instance);
    }

    [Fact]
    public void Validate_WhenPayloadIsMalformedJson_ReturnsFailureCaughtByJsonException()
    {
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        matcherMock.Setup(x => x.GetSupportWeight(It.IsAny<string>())).Returns(100);
        var sut = CreateSut(matcherMock.Object);
        var detail = new AuthorizationDetail("urn:test");

        var result = sut.Validate(detail, "{ malformed-json: true ");

        result.IsValid.Should().BeFalse("Malformed JSON should result in validation failure");
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Validate_WhenJsonIsEmpty_ReturnsFailure()
    {
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        var sut = CreateSut(matcherMock.Object);
        var detail = new AuthorizationDetail("urn:test");

        var result = sut.Validate(detail, "");

        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Validate_WhenDetailIsNull_ReturnsFailure()
    {
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        var sut = CreateSut(matcherMock.Object);

        var result = sut.Validate(null!, "{}");

        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Validate_WhenMatcherReturnsFalse_ReturnsFailure()
    {
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        matcherMock.Setup(x => x.GetSupportWeight(It.IsAny<string>())).Returns(100);
        matcherMock.Setup(x =>
                x.Matches(It.IsAny<AuthorizationDetail>(), It.IsAny<JsonElement>(), It.IsAny<RarValidationOptions>()))
            .Returns(false);

        var sut = CreateSut(matcherMock.Object);
        var detail = new AuthorizationDetail("urn:test");

        var result = sut.Validate(detail, "{}");

        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Validate_WhenMatcherThrows_CatchesAndReturnsFailure()
    {
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        matcherMock.Setup(x => x.GetSupportWeight(It.IsAny<string>())).Returns(100);
        matcherMock.Setup(x =>
                x.Matches(It.IsAny<AuthorizationDetail>(), It.IsAny<JsonElement>(), It.IsAny<RarValidationOptions>()))
            .Throws(new InvalidOperationException("Matcher error"));

        var sut = CreateSut(matcherMock.Object);
        var detail = new AuthorizationDetail("urn:test");

        var result = sut.Validate(detail, "{}");

        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ValidateByType_WhenNoMatchingTypeFound_ReturnsFailure()
    {
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        matcherMock.Setup(x => x.GetSupportWeight(It.IsAny<string>())).Returns(100);
        var sut = CreateSut(matcherMock.Object, true);
        var details = new[] { new AuthorizationDetail("urn:expected:type") };

        var result = sut.ValidateByType(details, "urn:different:type", "{}");

        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ValidateByType_WhenDetailsArrayIsEmpty_ReturnsFailure()
    {
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        var sut = CreateSut(matcherMock.Object);
        var details = Array.Empty<AuthorizationDetail>();

        var result = sut.ValidateByType(details, "urn:test", "{}");

        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void ValidateByType_WhenPayloadIsInvalidJson_ReturnsFailure()
    {
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        matcherMock.Setup(x => x.GetSupportWeight(It.IsAny<string>())).Returns(100);
        var sut = CreateSut(matcherMock.Object);
        var details = new[] { new AuthorizationDetail("urn:test") };

        var result = sut.ValidateByType(details, "urn:test", "{ invalid json");

        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ValidateByType_WhenMatchingTypeFound_ValidatesSuccessfully()
    {
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        matcherMock.Setup(x => x.GetSupportWeight(It.IsAny<string>())).Returns(100);
        matcherMock.Setup(x =>
                x.Matches(It.IsAny<AuthorizationDetail>(), It.IsAny<JsonElement>(), It.IsAny<RarValidationOptions>()))
            .Returns(true);

        var sut = CreateSut(matcherMock.Object);
        var detail = new AuthorizationDetail("urn:test");
        var details = new[] { detail };

        var result = sut.ValidateByType(details, "urn:test", "{}");

        result.IsValid.Should().BeTrue();
        result.MatchedDetail.Should().Be(detail);
    }

    [Fact]
    public void ValidateByType_WhenCaseSensitiveDisabled_FindsMatchCaseInsensitively()
    {
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        matcherMock.Setup(x => x.GetSupportWeight(It.IsAny<string>())).Returns(100);
        matcherMock.Setup(x =>
                x.Matches(It.IsAny<AuthorizationDetail>(), It.IsAny<JsonElement>(), It.IsAny<RarValidationOptions>()))
            .Returns(true);

        var sut = CreateSut(matcherMock.Object);
        var detail = new AuthorizationDetail("urn:test:type");
        var details = new[] { detail };

        var result = sut.ValidateByType(details, "URN:TEST:TYPE", "{}");

        result.IsValid.Should().BeTrue("Case-insensitive comparison should match");
    }

    [Fact]
    public void Validate_WithValidPayloadAndMatchingDetail_ReturnsSuccess()
    {
        var matcherMock = new Mock<IAuthorizationDetailMatcher>();
        matcherMock.Setup(x => x.GetSupportWeight(It.IsAny<string>())).Returns(100);
        matcherMock.Setup(x =>
                x.Matches(It.IsAny<AuthorizationDetail>(), It.IsAny<JsonElement>(), It.IsAny<RarValidationOptions>()))
            .Returns(true);

        var sut = CreateSut(matcherMock.Object);
        var detail = new AuthorizationDetail("urn:valid:type");

        var result = sut.Validate(detail, "{\"type\":\"urn:valid:type\"}");

        result.IsValid.Should().BeTrue();
        result.MatchedDetail.Should().Be(detail);
    }
}
