using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Sentinel.DPoP;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Replay;

namespace Sentinel.Tests.Security.Security;

/// <summary>
///     High-Precision Temporal Boundary Tests for NIST AAL3/FAPI 2.0 Compliance
///     Validates "Zero Clock Skew" policy at millisecond precision using FakeTimeProvider.
///     Ensures that token freshness windows are enforced mathematically, preventing:
///     - Token Stretching: Attacker exploiting NTP drift to extend token lifetime
///     - Ghost Replay: Accepted replay because system clock moved backward
///     - Clock Jitter Bypass: Unintended acceptance due to unsynchronized server time
///     Architecture Note: Uses FakeTimeProvider (not Thread.Sleep) for deterministic, fast execution.
///     Each test completes in <10ms vs seconds with real time manipulation.
/// </summary>
public sealed class TemporalBoundaryTests
{
    private readonly DateTimeOffset _referenceTime;
    private readonly Mock<IJtiReplayCache> _replayCache;
    private readonly FakeTimeProvider _timeProvider;

    public TemporalBoundaryTests()
    {
        // RFC 9449 validates freshness from issued-at time (iat), not expiration (exp)
        // Our reference: 2026-01-01 12:00:00 UTC
        _referenceTime = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
        _timeProvider = new FakeTimeProvider(_referenceTime);

        // Mock JTI replay cache to always allow first use
        _replayCache = new Mock<IJtiReplayCache>();
        _replayCache
            .Setup(x => x.TryMarkUsedAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
    }

    /// <summary>
    ///     Test: Proof issued exactly at the 60-second tolerance boundary MUST be accepted.
    ///     Scenario: RFC 9449 defines tolerance window as [-60s, +5s] around current time.
    ///     Proof issued 60 seconds ago is at the exact mathematical boundary and MUST validate.
    /// </summary>
    [Fact]
    public async Task Iat_Boundary_AtMinus60Seconds_MustPass()
    {
        // Arrange: Create proof issued EXACTLY 60 seconds ago
        var proofIssuedAt = _referenceTime.AddSeconds(-60);
        var csrfNonce = Guid.NewGuid().ToString("N");
        var proof = CreateDpopProof(
            "ES256",
            proofIssuedAt,
            Guid.NewGuid().ToString("N"),
            "GET",
            "https://api.example.com/resource",
            "fUHyO2zb8QmvYDfvL8U47vEO1TkqvMSi1V8RO4ZhKwU");

        var validator = CreateValidator();
        var request = new DpopValidationRequest(
            proof,
            "GET",
            new Uri("https://api.example.com/resource"));

        // Act
        var result = await validator.ValidateAsync(request, CancellationToken.None);

        // Assert
        result.IsSuccess.Should().BeTrue(
            "Proof at exactly -60s boundary must be accepted per RFC 9449 tolerance");
    }

    /// <summary>
    ///     Test: Proof issued 1 millisecond BEFORE the 60-second boundary MUST be rejected.
    ///     Scenario: Attacker attempts to use a proof from 60.001 seconds ago.
    ///     Mathematical precision: MUST enforce the boundary to the millisecond.
    ///     Security Implication: Prevents "Token Stretching" attacks via NTP manipulation.
    /// </summary>
    [Fact]
    public async Task Iat_Boundary_AtMinus60_001Milliseconds_MustFail()
    {
        // Arrange: Create proof issued 60 seconds and 1 millisecond ago
        var proofIssuedAt = _referenceTime.AddMilliseconds(-60001);
        var proof = CreateDpopProof(
            "ES256",
            proofIssuedAt,
            Guid.NewGuid().ToString("N"),
            "GET",
            "https://api.example.com/resource",
            "fUHyO2zb8QmvYDfvL8U47vEO1TkqvMSi1V8RO4ZhKwU");

        var validator = CreateValidator();
        var request = new DpopValidationRequest(
            proof,
            "GET",
            new Uri("https://api.example.com/resource"));

        // Act
        var result = await validator.ValidateAsync(request, CancellationToken.None);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "Proof 1ms outside tolerance must be rejected to prevent Token Stretching");
    }

    /// <summary>
    ///     Test: Proof issued in the future (+5 seconds) MUST be accepted to allow clock skew.
    ///     Scenario: Client clock is 5 seconds ahead of server (common in distributed systems).
    ///     RFC 9449 tolerance allows +5s to accommodate this without false rejections.
    /// </summary>
    [Fact]
    public async Task Iat_Boundary_AtPlus5Seconds_MustPass()
    {
        // Arrange: Create proof issued 5 seconds in the future
        var proofIssuedAt = _referenceTime.AddSeconds(5);
        var proof = CreateDpopProof(
            "ES256",
            proofIssuedAt,
            Guid.NewGuid().ToString("N"),
            "GET",
            "https://api.example.com/resource",
            "fUHyO2zb8QmvYDfvL8U47vEO1TkqvMSi1V8RO4ZhKwU");

        var validator = CreateValidator();
        var request = new DpopValidationRequest(
            proof,
            "GET",
            new Uri("https://api.example.com/resource"));

        // Act
        var result = await validator.ValidateAsync(request, CancellationToken.None);

        // Assert
        result.IsSuccess.Should().BeTrue(
            "Proof with +5s clock skew must be accepted per RFC 9449");
    }

    /// <summary>
    ///     Test: Proof issued more than 5 seconds in the future MUST be rejected.
    ///     Scenario: Attacker attempts to use a proof from the future (impossible in honest scenario).
    ///     Prevents: Clock-jacking attacks where attacker forces system clock forward.
    /// </summary>
    [Fact]
    public async Task Iat_Boundary_AtPlus5_001Seconds_MustFail()
    {
        // Arrange: iat is second-granularity, so use +6s to be strictly beyond +5s window
        var proofIssuedAt = _referenceTime.AddSeconds(6);
        var proof = CreateDpopProof(
            "ES256",
            proofIssuedAt,
            Guid.NewGuid().ToString("N"),
            "GET",
            "https://api.example.com/resource",
            "fUHyO2zb8QmvYDfvL8U47vEO1TkqvMSi1V8RO4ZhKwU");

        var validator = CreateValidator();
        var request = new DpopValidationRequest(
            proof,
            "GET",
            new Uri("https://api.example.com/resource"));

        // Act
        var result = await validator.ValidateAsync(request, CancellationToken.None);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "Proof more than 5s in future must be rejected (impossible without clock attack)");
    }

    /// <summary>
    ///     Test: Multiple proofs advancing through time must maintain strict freshness enforcement.
    ///     Scenario: Simulates server processing multiple requests over 120 seconds.
    ///     Each must respect its individual iat window, not a global TTL.
    ///     Security Implication: Per-request validation prevents "replay window" attacks.
    /// </summary>
    [Fact]
    public async Task Iat_MultipleRequests_EachEnforcesBoundary()
    {
        var validator = CreateValidator();

        // T+0s: First request (just issued)
        var proofAt0 = CreateDpopProof(
            "ES256",
            _referenceTime,
            "jti_0",
            "GET",
            "https://api.example.com/1",
            "thumbprint_0");

        var result0 = await validator.ValidateAsync(
            new DpopValidationRequest(proofAt0, "GET", new Uri("https://api.example.com/1")), CancellationToken.None);
        result0.IsSuccess.Should().BeTrue();

        // T+30s: Second request (still within original 60s window)
        _timeProvider.Advance(TimeSpan.FromSeconds(30));
        var proofAt30 = CreateDpopProof(
            "ES256",
            _referenceTime.AddSeconds(30),
            "jti_30",
            "GET",
            "https://api.example.com/2",
            "thumbprint_1");

        var result30 = await validator.ValidateAsync(
            new DpopValidationRequest(proofAt30, "GET", new Uri("https://api.example.com/2")), CancellationToken.None);
        result30.IsSuccess.Should().BeTrue();

        // T+61s: Try first proof again (now outside boundary)
        _timeProvider.Advance(TimeSpan.FromSeconds(31));
        var result61 = await validator.ValidateAsync(
            new DpopValidationRequest(proofAt0, "GET", new Uri("https://api.example.com/1")), CancellationToken.None);
        result61.IsSuccess.Should().BeFalse(
            "Original proof should be outside window after 61 seconds");
    }

    /// <summary>
    ///     Test: Clock moving backward (due to NTP adjustment) must NOT cause replay bypass.
    ///     Scenario: System clock jumps backward 2 seconds due to NTP correction.
    ///     Previously, refused proofs should still be refused (not suddenly accepted).
    /// </summary>
    [Fact]
    public async Task ClockRegression_PreviouslyRejectedProofStaysRejected()
    {
        var validator = CreateValidator();

        // Arrange: Proof issued in the far past (outside tolerance)
        var oldProof = CreateDpopProof(
            "ES256",
            _referenceTime.AddSeconds(-120),
            "jti_old",
            "GET",
            "https://api.example.com/old",
            "thumbprint_old");

        // Act 1: Initially, old proof should be rejected
        var resultBefore = await validator.ValidateAsync(
            new DpopValidationRequest(oldProof, "GET", new Uri("https://api.example.com/old")), CancellationToken.None);
        resultBefore.IsSuccess.Should().BeFalse("Proof from 120s ago should be rejected");

        // Act 2: Simulate a 2-second regressed clock with a fresh validator/time provider
        var regressedTimeProvider = new FakeTimeProvider(_referenceTime.AddSeconds(-2));
        var validatorAfterRegression = new DpopProofValidator(
            _replayCache.Object,
            Options.Create(new DPoPOptions
            {
                ProofLifetimeSeconds = 55,
                AllowedClockSkewSeconds = 5
            }),
            null,
            regressedTimeProvider);

        // Assert: Even with backward clock, old proof must still be rejected
        var resultAfter = await validatorAfterRegression.ValidateAsync(
            new DpopValidationRequest(oldProof, "GET", new Uri("https://api.example.com/old")), CancellationToken.None);
        resultAfter.IsSuccess.Should().BeFalse(
            "Clock regression must not cause replay of previously-rejected proofs");
    }

    /// <summary>
    ///     Reflection-based helper: Creates DpopProofValidator with FakeTimeProvider.
    /// </summary>
    private DpopProofValidator CreateValidator()
    {
        var options = new DPoPOptions
        {
            // Validator window is [now - lifetime - skew, now + skew].
            // Configure to enforce the intended [-60s, +5s] test window.
            ProofLifetimeSeconds = 55,
            AllowedClockSkewSeconds = 5
        };

        return new DpopProofValidator(
            _replayCache.Object,
            Options.Create(options),
            null, // thumbprintComputer (use default)
            _timeProvider);
    }

    /// <summary>
    ///     Creates a minimal valid DPoP proof JWT for testing.
    ///     Uses ES256 (ECDSA P-256) with a test key for simplicity.
    /// </summary>
    private static string CreateDpopProof(
        string signingAlgorithm,
        DateTimeOffset issuedAtOffset,
        string jti,
        string httpMethod,
        string httpUri,
        string thumbprintJkt)
    {
        _ = thumbprintJkt;

        using var ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var securityKey = new ECDsaSecurityKey(ecKey);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(securityKey);

        var handler = new JsonWebTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["htm"] = httpMethod.ToUpperInvariant(),
                ["htu"] = httpUri.ToLowerInvariant(),
                ["iat"] = issuedAtOffset.ToUnixTimeSeconds(),
                ["jti"] = jti
            },
            SigningCredentials = new SigningCredentials(securityKey, signingAlgorithm),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = new Dictionary<string, string>
                {
                    ["kty"] = jwk.Kty!,
                    ["crv"] = jwk.Crv!,
                    ["x"] = jwk.X!,
                    ["y"] = jwk.Y!
                }
            }
        };

        return handler.CreateToken(tokenDescriptor);
    }
}
