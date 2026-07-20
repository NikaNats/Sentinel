using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Infrastructure.Cryptography;

namespace Sentinel.Tests.Unit.Unit;

/// <summary>
///     High-assurance cryptographic unit tests for MlDsaSignatureVerifier.
///     Validates FIPS 204 ML-DSA signature verification using native .NET 10 APIs.
/// </summary>
public sealed class MlDsaSignatureVerifierTests
{
    private readonly MlDsaSignatureVerifier _sut = new(NullLogger<MlDsaSignatureVerifier>.Instance);

    [Fact(DisplayName = "✅ Invariant: Mathematically valid ML-DSA-65 signature must verify successfully")]
    public void Verify_ValidMlDsa65Signature_ReturnsTrue()
    {
        if (!MLDsa.IsSupported)
        {
            return;
        }

        // Arrange: Generate a real, native .NET 10 ML-DSA-65 key pair (NIST Level 3)
        using var mldsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var publicKey = mldsa.ExportMLDsaPublicKey();

        var input = "sentinel-high-assurance-pqc-test-payload"u8.ToArray();
        var signature = mldsa.SignData(input);

        // Act: Verify using our newly integrated service
        var result = _sut.Verify("ML-DSA-65", publicKey, input, signature);

        // Assert: Cryptographic verification must pass
        result.Should().BeTrue("A mathematically correct post-quantum signature must be accepted.");
    }

    [Fact(DisplayName = "🛡️ Adversarial: Tampered ML-DSA signature must fail-closed")]
    public void Verify_TamperedMlDsaSignature_ReturnsFalse()
    {
        if (!MLDsa.IsSupported)
        {
            return;
        }

        // Arrange: Generate valid signature
        using var mldsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
        var publicKey = mldsa.ExportMLDsaPublicKey();
        var input = "secure-data"u8.ToArray();
        var signature = mldsa.SignData(input);

        // Corrupt the signature by flipping the last byte (Simulation of data corruption / attack)
        signature[^1] ^= 0xFF;

        // Act: Verify modified payload
        var result = _sut.Verify("ML-DSA-44", publicKey, input, signature);

        // Assert: Must reject (Fail-Closed)
        result.Should().BeFalse("Any cryptographic modification to the signature must trigger rejection.");
    }

    [Fact(DisplayName = "🛡️ Adversarial: Mismatched public key must fail-closed")]
    public void Verify_MismatchedPublicKey_ReturnsFalse()
    {
        if (!MLDsa.IsSupported)
        {
            return;
        }

        // Arrange: Generate two separate key pairs
        using var mldsa1 = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
        using var mldsa2 = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);

        var publicKey2 = mldsa2.ExportMLDsaPublicKey(); // Mismatched key (Key-Swap Attack simulation)
        var input = "secure-data"u8.ToArray();
        var signature = mldsa1.SignData(input); // Signed by key 1

        // Act: Verify against mismatched public key
        var result = _sut.Verify("ML-DSA-44", publicKey2, input, signature);

        // Assert
        result.Should().BeFalse("Signature verified against the wrong public key must be rejected.");
    }

    [Fact(DisplayName = "🛡️ Dimension Check: Rejects public key or signature with invalid FIPS 204 dimensions")]
    public void Verify_InvalidKeyOrSignatureDimensions_ReturnsFalse()
    {
        if (!MLDsa.IsSupported)
        {
            return;
        }

        // Arrange: Generate correct ML-DSA-44 key and signature (NIST Level 1)
        using var mldsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
        var publicKey = mldsa.ExportMLDsaPublicKey();
        var input = "secure-data"u8.ToArray();
        var signature = mldsa.SignData(input);

        // Act: Attempt to verify using ML-DSA-65 algorithm (size dimension mismatch!)
        var result = _sut.Verify("ML-DSA-65", publicKey, input, signature);

        // Assert: Must reject instantly without calling native cryptographic verification
        result.Should().BeFalse("Dimension mismatch between ML-DSA-44 key dimensions and ML-DSA-65 parameters must fail closed.");
    }

    [Theory(DisplayName = "❌ Boundary: Null, empty, or whitespace algorithm identifiers must fail closed")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Verify_NullOrEmptyAlgorithm_ReturnsFalse(string? invalidAlgorithm)
    {
        // Act
        var result = _sut.Verify(invalidAlgorithm!, [1, 2, 3], [4, 5], [6, 7]);

        // Assert
        result.Should().BeFalse("Null, empty, or whitespace algorithm identifiers must fail-closed safely.");
    }

    [Fact(DisplayName = "❌ Boundary: Unsupported algorithm names must be rejected gracefully")]
    public void Verify_UnsupportedAlgorithm_ReturnsFalse()
    {
        // Act
        var result = _sut.Verify("INVALID-ALGORITHM-NAME", [1, 2, 3], [4, 5], [6, 7]);

        // Assert
        result.Should().BeFalse("Unsupported algorithm names must fail-closed without crashing.");
    }
}
