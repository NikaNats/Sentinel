using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.SdJwt;

namespace Sentinel.Tests.Unit.Unit;

public sealed class SdJwtPresenterTests
{
    private readonly SdJwtPresenter _sut;
    private readonly Mock<ISdJwtTokenValidator> _validatorMock = new();

    public SdJwtPresenterTests()
    {
        _sut = new SdJwtPresenter(_validatorMock.Object, new SdJwtVerificationOptions(),
            NullLogger<SdJwtPresenter>.Instance);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public async Task VerifyPresentationAsync_WhenPresentationIsEmpty_ReturnsFailure(string presentation)
    {
        // Act
        var result = await _sut.VerifyPresentationAsync(presentation ?? "", "audience");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }

    [Theory]
    [InlineData("just-one-part")]
    [InlineData("part1~toomanyparts")]
    public async Task VerifyPresentationAsync_WhenFormatIsInvalid_ReturnsFailure(string presentation)
    {
        // Act
        var result = await _sut.VerifyPresentationAsync(presentation, "audience");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task VerifyPresentationAsync_WhenIssuerValidationFails_ReturnsFailure()
    {
        // Arrange
        _validatorMock
            .Setup(x => x.ValidateIssuerTokenAsync(It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(SdJwtIssuerTokenValidationResult.Failure("Issuer invalid"));

        // Act
        var result = await _sut.VerifyPresentationAsync("issuer~kb", "audience");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().Contain("invalid");
    }

    [Fact]
    public async Task VerifyPresentationAsync_WhenTokenValidationThrows_CatchesAndFailsClosed()
    {
        // Arrange
        _validatorMock
            .Setup(x => x.ValidateIssuerTokenAsync(It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Network down"));

        // Act
        var result = await _sut.VerifyPresentationAsync("issuer~kb", "audience");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task VerifyPresentationAsync_WhenOperationCancelled_ReturnsFailure()
    {
        // Arrange
        _validatorMock
            .Setup(x => x.ValidateIssuerTokenAsync(It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());

        // Act
        var result = await _sut.VerifyPresentationAsync("issuer~kb", "audience");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task VerifyPresentationAsync_WhenMultipleDisclosures_ParsesCorrectly()
    {
        // Arrange - presentation with multiple disclosures: issuer~disclosure1~disclosure2~kb
        var presentation = "issuer~disclosure1~disclosure2~kb";

        _validatorMock
            .Setup(x => x.ValidateIssuerTokenAsync(It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(SdJwtIssuerTokenValidationResult.Failure("Validation fails for testing boundary"));

        // Act
        var result = await _sut.VerifyPresentationAsync(presentation, "audience");

        // Assert
        // Should attempt validation and fail gracefully
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyPresentationAsync_WithMissingIssuerJwt_ReturnsFailure()
    {
        // Arrange - presentation starts with ~ (empty issuer)
        var presentation = "~disclosure~kb";

        // Act
        var result = await _sut.VerifyPresentationAsync(presentation, "audience");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task VerifyPresentationAsync_WithMissingKeyBinding_ReturnsFailure()
    {
        // Arrange - presentation ends with ~ (empty key binding)
        var presentation = "issuer~disclosure~";

        // Act
        var result = await _sut.VerifyPresentationAsync(presentation, "audience");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }
}
