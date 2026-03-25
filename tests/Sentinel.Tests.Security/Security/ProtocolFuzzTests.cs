using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.SdJwt;
using Sentinel.Tests.Security.Helpers;
using Xunit;

namespace Sentinel.Tests.Security;

/// <summary>
/// Negative Protocol Fuzzing Tests
///
/// These tests ensure that security validators fail CLOSED (return failure results)
/// rather than throwing unhandled exceptions when presented with malformed input.
///
/// In .NET 10 Native AOT environments with microsecond performance targets,
/// an uncaught NullReferenceException or IndexOutOfRangeException in a SIMD-optimized
/// JSON parser doesn't just log an error—it can crash the entire high-performance pipeline.
///
/// This test suite applies deterministic mutations (not random fuzzing) to cryptographic
/// structures to ensure robust error handling across:
/// - RFC 9449 DPoP Proof validation (via IDpopProofValidator interface)
/// - RFC 9901 Selective Disclosure JWT processing
/// - Base64Url decoding edge cases
/// - JSON parsing attacks (deeply nested, overlong UTF-8, null bytes, etc.)
///
/// Success criteria: All fuzzed inputs result in controlled SecurityResult.Failure()
/// or SdJwtVerificationResult.Failure(), never an unhandled exception.
/// </summary>
public sealed class ProtocolFuzzTests
{
    private readonly IDpopProofValidator _dpopValidator;
    private readonly SdJwtPresenter _sdJwtPresenter;
    private readonly Mock<ISdJwtTokenValidator> _tokenValidatorMock;

    public ProtocolFuzzTests()
    {
        // Set up validators with mocked infrastructure
        var replayCache = new Mock<IJtiReplayCache>();
        replayCache.Setup(x => x.TryMarkUsedAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Use reflection to instantiate the internal DpopProofValidator class
        var dpopType = Type.GetType("Sentinel.DPoP.DpopProofValidator, Sentinel.DPoP");
        if (dpopType != null)
        {
            _dpopValidator = (IDpopProofValidator?)Activator.CreateInstance(dpopType, replayCache.Object)
                ?? throw new InvalidOperationException("Failed to create DpopProofValidator");
        }
        else
        {
            throw new InvalidOperationException("DpopProofValidator type not found");
        }

        _tokenValidatorMock = new Mock<ISdJwtTokenValidator>();
        _sdJwtPresenter = new SdJwtPresenter(
            _tokenValidatorMock.Object,
            new SdJwtVerificationOptions(),
            NullLogger<SdJwtPresenter>.Instance);
    }

    /// <summary>
    /// Tests that IDpopProofValidator implementation gracefully handles all structural mutations
    /// without throwing unhandled exceptions.
    ///
    /// Mutations tested:
    /// - Wrong number of JWT segments
    /// - Illegal Base64Url characters
    /// - Poison payloads (null bytes, overlong UTF-8, deeply nested JSON)
    /// - Bit-flipping corruption
    /// - Truncation attacks
    /// - Empty segments
    /// </summary>
    [Theory]
    [MemberData(nameof(GetPoisonedDpopProofs))]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public async Task DpopValidator_MustNotThrow_WhenPresentedWithFuzzedInput(string fuzzedProof)
    {
        // Arrange
        var request = new DpopValidationRequest(
            dpopHeader: fuzzedProof,
            httpMethod: "POST",
            httpUri: new Uri("https://api.sentinel.com/v1/transfer"),
            accessToken: "valid.access.token"
        );

        // Act & Assert
        // CRITICAL: We wrap in a try-catch to detect NAKED exceptions.
        // The validator should ALWAYS return a SecurityResult (success or failure),
        // never throw an unhandled exception.
        try
        {
            var result = await _dpopValidator.ValidateAsync(request, TestContext.Current.CancellationToken);

            // Verify we got a result object (not null)
            result.Should().NotBeNull("Validator should always return a SecurityResult");

            // Fuzzed protocol input should NEVER validate successfully
            result.IsSuccess.Should().BeFalse(
                "Fuzzed/malformed DPoP proof should never pass validation");
        }
        catch (ArgumentNullException ex)
        {
            // ArgumentNullException is acceptable for invalid input parameters
            ex.ParamName.Should().NotBeNullOrEmpty();
        }
        catch (ArgumentException ex)
        {
            // ArgumentException is acceptable for malformed input
            ex.Message.Should().NotBeNullOrEmpty();
        }
        catch (OperationCanceledException)
        {
            // OperationCanceledException is acceptable if test is cancelled
        }
        catch (Exception ex)
        {
            // Any other exception indicates a vulnerability in the validator
            Assert.Fail(
                $"DPoP validator exploded with {ex.GetType().Name}: {ex.Message}\n" +
                $"Fuzzed input: {fuzzedProof}\n" +
                $"Stack trace: {ex.StackTrace}");
        }
    }

    /// <summary>
    /// Tests that SdJwtPresenter gracefully handles all structural mutations
    /// without throwing unhandled exceptions.
    ///
    /// SD-JWT uses '~' as segment separator (different from JWT's '.'),
    /// creating additional attack surface for separator confusion and boundary attacks.
    /// </summary>
    [Theory]
    [MemberData(nameof(GetPoisonedSdJwtPresentations))]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public async Task SdJwtPresenter_MustNotThrow_WhenPresentedWithFuzzedInput(string fuzzedPresentation)
    {
        // Act & Assert
        try
        {
            var result = await _sdJwtPresenter.VerifyPresentationAsync(fuzzedPresentation, "sentinel-api", cancellationToken: TestContext.Current.CancellationToken);

            // Verify we got a result object
            result.Should().NotBeNull("Presenter should always return a SdJwtVerificationResult");

            // Fuzzed input should fail validation
            result.IsValid.Should().BeFalse(
                "Fuzzed/malformed SD-JWT should never pass validation");
        }
        catch (ArgumentNullException ex)
        {
            // ArgumentNullException is acceptable for null string input
            ex.ParamName.Should().NotBeNullOrEmpty();
        }
        catch (ArgumentException ex)
        {
            // ArgumentException is acceptable for malformed input
            ex.Message.Should().NotBeNullOrEmpty();
        }
        catch (OperationCanceledException)
        {
            // OperationCanceledException is acceptable if test is cancelled
        }
        catch (Exception ex)
        {
            // Any other exception indicates a vulnerability
            Assert.Fail(
                $"SD-JWT presenter exploded with {ex.GetType().Name}: {ex.Message}\n" +
                $"Fuzzed input: {fuzzedPresentation}\n" +
                $"Stack trace: {ex.StackTrace}");
        }
    }

    /// <summary>
    /// Test that empty string input is handled gracefully.
    /// Empty strings are a common attack vector for buffer underruns.
    /// </summary>
    [Fact]
    public async Task DpopValidator_WithEmptyString_ReturnsFailure()
    {
        // Arrange
        var request = new DpopValidationRequest(
            dpopHeader: string.Empty,
            httpMethod: "POST",
            httpUri: new Uri("https://api.sentinel.com/v1/transfer"),
            accessToken: "token"
        );

        // Act
        var result = await _dpopValidator.ValidateAsync(request, TestContext.Current.CancellationToken);

        // Assert
        result.IsSuccess.Should().BeFalse();
    }

    /// <summary>
    /// Test that null string input is handled gracefully.
    /// Should throw ArgumentNullException, NOT a NullReferenceException later in parsing.
    /// </summary>
    [Fact]
    public async Task DpopValidator_WithNullString_ThrowsArgumentNullException()
    {
        // Arrange
        var request = new DpopValidationRequest(
            dpopHeader: null!,
            httpMethod: "POST",
            httpUri: new Uri("https://api.sentinel.com/v1/transfer"),
            accessToken: "token"
        );

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await _dpopValidator.ValidateAsync(request, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// Test that extremely long input doesn't cause stack overflow or buffer exhaustion.
    /// </summary>
    [Fact]
    public async Task DpopValidator_WithExtremelyLongInput_ReturnsFailure()
    {
        // Arrange
        var veryLongProof = new string('a', 1_000_000); // 1MB of 'a' characters
        var request = new DpopValidationRequest(
            dpopHeader: veryLongProof,
            httpMethod: "POST",
            httpUri: new Uri("https://api.sentinel.com/v1/transfer"),
            accessToken: "token"
        );

        // Act
        var result = await _dpopValidator.ValidateAsync(request, TestContext.Current.CancellationToken);

        // Assert
        result.IsSuccess.Should().BeFalse();
    }

    /// <summary>
    /// Test that special Unicode characters don't bypass the parser.
    /// Unicode Replacement Character (U+FFFD) and other edge cases.
    /// </summary>
    [Theory]
    [InlineData("\uFFFD")]           // Unicode Replacement Character
    [InlineData("\u0000")]           // Null character
    [InlineData("\xC0\xAF")]         // Overlong UTF-8 encoding of "/"
    [InlineData("\\u0000")]          // Escaped null
    public async Task DpopValidator_WithSpecialUnicodeCharacters_ReturnsFailure(string poison)
    {
        // Arrange
        var request = new DpopValidationRequest(
            dpopHeader: poison,
            httpMethod: "POST",
            httpUri: new Uri("https://api.sentinel.com/v1/transfer"),
            accessToken: "token"
        );

        // Act
        var result = await _dpopValidator.ValidateAsync(request, TestContext.Current.CancellationToken);

        // Assert
        result.IsSuccess.Should().BeFalse();
    }

    /// <summary>
    /// Test SD-JWT with separator confusion (using . instead of ~).
    /// </summary>
    [Fact]
    public async Task SdJwtPresenter_WithJwtSeparators_ReturnsFailure()
    {
        // Arrange
        var confusedPresentation = "issuer_jwt.disclosure1.kb_jwt"; // Wrong separators

        // Act
        var result = await _sdJwtPresenter.VerifyPresentationAsync(confusedPresentation, "sentinel-api", cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.IsValid.Should().BeFalse();
    }

    /// <summary>
    /// Test SD-JWT with missing components.
    /// </summary>
    [Fact]
    public async Task SdJwtPresenter_WithMissingComponents_ReturnsFailure()
    {
        // Arrange - Only the issuer JWT, no disclosures or key binding
        var incompletePresentation = "issuer_jwt_only";

        // Act
        var result = await _sdJwtPresenter.VerifyPresentationAsync(incompletePresentation, "sentinel-api", cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.IsValid.Should().BeFalse();
    }

    /// <summary>
    /// Data source for DPoP proof mutations.
    /// Yields all poisoned variants of a valid DPoP structure.
    /// </summary>
    public static IEnumerable<object[]> GetPoisonedDpopProofs()
    {
        // Create a baseline valid JWT-like structure for mutations
        // (Note: This won't validate against real keys, but serves as structural template)
        var validProofTemplate = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7ImtpdCI6IjEifX0." +
                                 "eyJqdGkiOiIxMjMiLCJodHRwX3VyaSI6Imh0dHBzOi8vYXBpLmV4YW1wbGUuY29tIiwiaHR0cF9tZXRob2QiOiJQT1NUIn0." +
                                 "signature";

        // Generate all mutations from TokenPoisoner
        return TokenPoisoner.GenerateMutations(validProofTemplate)
            .Select(x => new object[] { x })
            .Take(50); // Limit to 50 mutations for reasonable test runtime
    }

    /// <summary>
    /// Data source for SD-JWT presentation mutations.
    /// Yields all poisoned variants of a valid SD-JWT structure.
    /// </summary>
    public static IEnumerable<object[]> GetPoisonedSdJwtPresentations()
    {
        // Baseline valid SD-JWT presentation structure
        var validSdJwtTemplate = "eyJhbGciOiJFUzI1NiIsInR5cCI6InNkLWp3dCJ9." +
                                 "eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn0." +
                                 "sig~disclosure1~disclosure2~" +
                                 "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJzZW50aW5lbC1hcGkifQ.kb_sig";

        // Generate all mutations
        return TokenPoisoner.GenerateSdJwtMutations(validSdJwtTemplate)
            .Select(x => new object[] { x });
    }
}
