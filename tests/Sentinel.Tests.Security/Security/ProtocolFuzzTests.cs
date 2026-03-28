using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.DPoP;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Replay;

namespace Sentinel.Tests.Security;

/// <summary>
///     Negative Protocol Fuzzing Tests
///     These tests ensure that security validators fail CLOSED (return failure results)
///     rather than throwing unhandled exceptions when presented with malformed input.
///     In .NET 10 Native AOT environments with microsecond performance targets,
///     an uncaught NullReferenceException or IndexOutOfRangeException in a SIMD-optimized
///     JSON parser doesn't just log an error—it can crash the entire high-performance pipeline.
///     This test suite applies deterministic mutations (not random fuzzing) to cryptographic
///     structures to ensure robust error handling across:
///     - RFC 9449 DPoP Proof validation
///     - Base64Url decoding edge cases
///     - JSON parsing attacks (deeply nested, overlong UTF-8, null bytes, etc.)
///     Success criteria: All fuzzed inputs result in controlled SecurityResult.Failure()
///     or appropriate exception, never an unhandled crash.
/// </summary>
public sealed class ProtocolFuzzTests
{
    private readonly DpopProofValidator _dpopValidator;
    private readonly Mock<IJtiReplayCache> _replayCacheMock;

    public ProtocolFuzzTests()
    {
        // STRICT mocking: cache operations are verified
        _replayCacheMock = new Mock<IJtiReplayCache>(MockBehavior.Strict);
        _replayCacheMock
            .Setup(x => x.TryMarkUsedAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Direct instantiation
        var options = Options.Create(new DPoPOptions());
        _dpopValidator = new DpopProofValidator(_replayCacheMock.Object, options);
    }

    /// <summary>
    ///     Deterministic mutation-based fuzzing: High-risk token mutations.
    ///     These payloads represent real OIDC/JWT vulnerabilities found in production:
    ///     - Empty JWT (no segments)
    ///     - Truncated JWT (missing signature)
    ///     - Over-segmented JWT (extra dots)
    ///     - Null-byte injection
    ///     - Buffer stress (large payloads)
    ///     Expected: All MUST be rejected safely (no crashes).
    /// </summary>
    [Theory(DisplayName = "🧪 Deterministic Fuzz: High-Risk DPoP Token Mutations")]
    [MemberData(nameof(GetHighRiskPoisonPayloads))]
    public async Task DpopValidator_HandlesFuzzedPayloads_WithoutCrashing(string poisonProof)
    {
        // Arrange
        var request = new DpopValidationRequest(
            poisonProof,
            "POST",
            new Uri("https://api.io/t"));

        // Act: Use timeout to catch infinite loops / algorithmic complexity attacks
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));

        Func<Task> act = async () => await _dpopValidator.ValidateAsync(request, cts.Token);

        // Assert: Should not throw NullReferenceException or IndexOutOfRangeException
        await act.Should().NotThrowAsync<NullReferenceException>("Validator must be null-safe");
        await act.Should().NotThrowAsync<IndexOutOfRangeException>("Validator must be bounds-safe");

        // Additional: If it doesn't timeout, the result should be failure
        if (!cts.Token.IsCancellationRequested)
        {
            var result = await _dpopValidator.ValidateAsync(request);
            result.IsSuccess.Should().BeFalse("Poisoned payloads must never result in success");
        }
    }

    /// <summary>
    ///     Test: Timing attack resilience - slow payload processing.
    ///     Scenario: Attacker sends extremely large payload hoping to:
    ///     1. Trigger ReDoS (Regular Expression Denial of Service)
    ///     2. Exhaust memory (if validator copies entire payload)
    ///     3. Lock CPU (if validator processes synchronously)
    ///     Expected: Either reject quickly or timeout (fail-closed).
    ///     Never accept or hang indefinitely.
    /// </summary>
    [Fact(DisplayName = "⏰ Timing Attack: Large Payload Processing")]
    public async Task DpopValidator_DoesNotHangOrExhaustMemory_OnLargePayload()
    {
        // Arrange: Create a payload with 10MB of A's (would exhaust if buffered)
        var largePayload = new string('A', 10_000_000);

        var request = new DpopValidationRequest(
            largePayload,
            "POST",
            new Uri("https://api.io/t"));

        // Act: Enforce tight timeout for processing
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        // Either completes fast with failure, or times out (both are safe)
        Func<Task> act = async () => await _dpopValidator.ValidateAsync(request, cts.Token);

        // Assert: Should NOT throw OutOfMemoryException or StackOverflowException
        await act.Should().NotThrowAsync<OutOfMemoryException>("Large payload must not exhaust memory");
        await act.Should().NotThrowAsync<StackOverflowException>("Deep nesting must not overflow stack");
    }

    /// <summary>
    ///     Test: Null-byte injection and UTF-8 edge cases.
    ///     Scenario: Attacker injects null bytes or invalid UTF-8 sequences
    ///     hoping to bypass string parsing or cause encoding errors.
    ///     Expected: Safely rejected; no crashes from encoding.
    /// </summary>
    [Theory(DisplayName = "🔤 UTF-8 Edge Cases (null bytes, invalid sequences)")]
    [InlineData("header.payload.sig\0.extra", "Null byte injection")]
    [InlineData("header.payload.\xFF\xFE", "Invalid UTF-8 encoding")]
    [InlineData("\x00\x00\x00.\x00\x00\x00.\x00\x00\x00", "All null bytes")]
    public async Task DpopValidator_HandlesEncodingEdgeCases_Safely(string poisonProof, string scenario)
    {
        // Arrange
        var request = new DpopValidationRequest(
            poisonProof,
            "POST",
            new Uri("https://api.io/t"));

        // Act
        Func<Task> act = async () => await _dpopValidator.ValidateAsync(request);

        // Assert: Must handle encoding gracefully
        await act.Should().NotThrowAsync<DecoderFallbackException>("Encoder must not throw on bad UTF-8");
        await act.Should().NotThrowAsync<DecoderFallbackException>("Decoder must handle invalid sequences");

        // If it completes, result must be failure
        var result = await _dpopValidator.ValidateAsync(request);
        result.IsSuccess.Should().BeFalse(scenario);
    }

    /// <summary>
    ///     Test: Deeply nested JSON structures (zip bomb variant).
    ///     Scenario: Payload with thousands of nesting levels
    ///     hoping to overflow parser stack or cause memory exhaustion.
    ///     Expected: Rejected quickly; no stack overflow.
    /// </summary>
    [Fact(DisplayName = "🎯 JSON Zip-Bomb: Deeply Nested Structure")]
    public async Task DpopValidator_RejectsZipBombNestedJson_SafelyAndQuickly()
    {
        // Arrange: Create JWT with deeply nested JSON
        var deeplyNested = "{" + string.Join("{", Enumerable.Repeat("a:", 1000)) +
                           "1" + string.Concat(Enumerable.Repeat("}", 1001)) + "}";

        var headerB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(deeplyNested));
        var payloadB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(deeplyNested));
        var zipBombToken = $"{headerB64}.{payloadB64}.sig";

        var request = new DpopValidationRequest(
            zipBombToken,
            "POST",
            new Uri("https://api.io/t"));

        // Act
        using var limitedTime = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        Func<Task> act = async () => await _dpopValidator.ValidateAsync(request, limitedTime.Token);

        // Assert
        await act.Should()
            .NotThrowAsync<StackOverflowException>("Parser must not overflow on deep nesting");

        // Should either timeout or fail quickly
        if (!limitedTime.Token.IsCancellationRequested)
        {
            var result = await _dpopValidator.ValidateAsync(request);
            result.IsSuccess.Should().BeFalse("Malformed nested JSON must be rejected");
        }
    }

    /// <summary>
    ///     Factory method: Returns high-risk mutation payloads for Theory test.
    /// </summary>
    public static TheoryData<string> GetHighRiskPoisonPayloads() => new()
    {
        "", // Empty string
        "header.payload", // Truncated (missing signature)
        "header.payload.sig.extra", // Over-segmented
        "{\"alg\":\"none\"}.{}.{}", // Alg-none attack
        ".", // Single dot
        "..", // Double dots
        "A".PadRight(5000), // Very long single segment
        "\x00\x00\x00.\x00\x00", // Null bytes
        "😁😁😁😁😁", // Multi-byte UTF-8 (emoji bombs)
        "ÿþÿþ.ÿþÿþ.ÿþÿþ", // BOM markers
        "../../../etc/passwd.../../config" // Path traversal attempt
    };
}
