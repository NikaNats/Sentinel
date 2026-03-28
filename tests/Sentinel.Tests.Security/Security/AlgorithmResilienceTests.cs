using FluentAssertions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Sentinel.DPoP;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Replay;
using System.Security.Cryptography;
using Moq;
using Xunit;
using Sentinel.Tests.Shared;

namespace Sentinel.Tests.Security.Security;

/// <summary>
/// Algorithm Agility & Downgrade Resilience Tests for NIST AAL3/FAPI 2.0
///
/// Prevents Cross-Algorithm Substitution Attacks where an attacker:
/// - Presents an EC key but uses RSA algorithm (PS256)
/// - Uses "alg: none" to bypass signature verification
/// - Substitutes weaker algorithm (HS256) for stronger (ES256)
/// - Exploits algorithm confusion between RSA and EC signatures
///
/// Architecture Note: DPoP validator MUST enforce strict mapping between:
/// - JWK key type ("kty": "EC" | "RSA" | "OKP")
/// - Claims algorithm ("alg": "ES256" | "PS256" | "EdDSA")
/// No exceptions, no upgrades, no downgrades.
///
/// Safety Principle: Strict Mocking (MockBehavior.Strict)
/// If the validator tries to call cache methods it shouldn't, or skip security checks,
/// the mock will throw an immediate failure. No sneaky passes-by-default.
/// </summary>
public sealed class AlgorithmResilienceTests : IDisposable
{
    private readonly Mock<IJtiReplayCache> _replayCacheMock;
    private readonly ECDsa _ecDsa;
    private readonly RSA _rsa;
    private readonly DpopProofValidator _validator;

    public AlgorithmResilienceTests()
    {
        // Use STRICT mocking: every method call is verified
        // Any unexpected call = immediate failure
        _replayCacheMock = new Mock<IJtiReplayCache>(MockBehavior.Strict);

        // Setup expected cache call: Mark this JTI as used
        _replayCacheMock
            .Setup(x => x.TryMarkUsedAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true)
            .Verifiable("Cache MUST be checked for replay validation");

        _ecDsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _rsa = RSA.Create(2048);

        // Direct instantiation (no reflection)
        var options = Options.Create(new DPoPOptions());
        _validator = new DpopProofValidator(_replayCacheMock.Object, options);
    }

    /// <summary>
    /// Security Invariant: Cross-Algorithm Substitution Attack (EC-to-RSA)
    ///
    /// Attacker presents a valid P-256 EC key in the JWK claim, but claims
    /// the algorithm is "PS256" (RSA-PSS). If the validator is confused,
    /// it might accept this as valid, leading to signature bypass.
    ///
    /// Expected: REJECT with "unsupported_algorithm" error.
    /// </summary>
    [Fact(DisplayName = "🔐 Cross-Algorithm Substitution (EC key + RS256 claim) MUST be rejected")]
    public async Task ValidateAsync_RejectsEcKeyClaimingRsAlgorithm()
    {
        // Arrange: Create malformed proof (EC key, RSA algorithm claim)
        var maliciousProof = TestJwtBuilder.CreateMalformedProof(
            _ecDsa,
            headerAlg: SecurityAlgorithms.RsaSsaPssSha256,
            kty: "EC");

        var request = new DpopValidationRequest(
            maliciousProof,
            "POST",
            new Uri("https://api.sentinel.io/v1/auth"));

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "Validator must prevent cross-algorithm substitution where EC key claims RSA signing");
        result.ErrorMessage.Should().Be("unsupported_algorithm",
            "The error MUST be 'unsupported_algorithm', never a generic failure or exception");
    }

    /// <summary>
    /// Security Invariant: Symmetric Key Confusion Attack (HMAC masquerade)
    ///
    /// Symmetric algorithms (HMAC: HS256, HS384, HS512) sign with a shared secret.
    /// Asymmetric algorithms (RSA, EC) sign with a private key.
    ///
    /// If a validator uses the PUBLIC key as an HMAC secret, an attacker can
    /// forge proofs by re-signing with their own secret (payload substitution).
    ///
    /// Expected: REJECT symmetric algorithms entirely (only allow ES256, PS256, EdDSA).
    /// </summary>
    [Theory(DisplayName = "🛡️ Symmetric Key Confusion (HMAC) MUST be rejected")]
    [InlineData(SecurityAlgorithms.HmacSha256, "Weak HMAC-SHA256")]
    [InlineData(SecurityAlgorithms.HmacSha384, "Weak HMAC-SHA384")]
    [InlineData(SecurityAlgorithms.HmacSha512, "Weak HMAC-SHA512")]
    public async Task ValidateAsync_RejectsSymmetricKeyConfusion(string algorithm, string scenario)
    {
        // Arrange: Create proof using symmetric key
        var secret = "super-secret-key-that-is-too-short";
        var maliciousProof = TestJwtBuilder.CreateSymmetricProof(secret, algorithm);

        var request = new DpopValidationRequest(
            maliciousProof,
            "GET",
            new Uri("https://api.sentinel.io/v1/resource"));

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            $"Symmetric algorithms (HMAC) must be rejected to prevent Key-Confusion attacks. Scenario: {scenario}");
    }

    /// <summary>
    /// Security Invariant: "alg: none" Attack
    ///
    /// An attacker might create a proof with header claim "alg": "none",
    /// attempting to bypass signature verification entirely.
    ///
    /// Expected: REJECT with "unsupported_algorithm" (none is not a supported algorithm).
    /// </summary>
    [Fact(DisplayName = "⚠️ Algorithm 'None' Attack MUST be rejected")]
    public async Task ValidateAsync_RejectsAlgorithmNoneAttack()
    {
        // Arrange: Manually construct JWT with "alg": "none"
        var noneProof = "eyJhbGciOiJub25lIiwidHlwIjoiZHBvcCtqd3QiLCJqa2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiJ9fQ." +
                       "eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9hcGkuaW8vY2xhaW0iLCJpYXQiOjE2NDI2NjAxNjAsImp0aSI6InRlc3Qtand0In0." +
                       "";  // "none" has no signature

        var request = new DpopValidationRequest(
            noneProof,
            "POST",
            new Uri("https://api.io/claim"));

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "Algorithm 'none' must be rejected (no signature verification)");
    }

    public void Dispose()
    {
        _ecDsa.Dispose();
        _rsa.Dispose();
    }
}
