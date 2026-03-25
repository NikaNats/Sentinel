using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Sentinel.DPoP;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Replay;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace Sentinel.Tests.Security.Security;

/// <summary>
/// Negative Cryptographic Validation: Weak Key Rejection
///
/// This suite tests rejection of keys that are mathematically "legal" but cryptographically "weak."
/// A library may be able to parse and use these keys, but security policy MUST reject them.
///
/// Modern standards (FIPS 186-5, RFC 8812) require:
/// - RSA: Modulus >= 2048 bits, Exponent >= 65537 (0x010001)
/// - EC: Only approved curves (P-256, P-384, P-521)
/// - Disallow: Weak curves (secp256k1), small exponents (e=3), short keys
///
/// These tests make explicit that accepting weak keys is a vulnerability,
/// not just a "conservative choice."
/// </summary>
public sealed class WeakKeyTests
{
    private readonly Mock<IJtiReplayCache> _mockReplayCache;

    public WeakKeyTests()
    {
        _mockReplayCache = new Mock<IJtiReplayCache>();
        _mockReplayCache
            .Setup(x => x.TryMarkUsedAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
    }

    /// <summary>
    /// Test: RSA key with exponent e=3 MUST be rejected (vulnerable to Coppersmith's Attack).
    ///
    /// Background: Coppersmith's Attack allows factorization of RSA modulus when:
    /// - Exponent is very small (e.g., e=3)
    /// - Multiple ciphertexts of the same plaintext exist
    ///
    /// FIPS 186-5 Requirement: e >= 65537 (0x010001)
///
    /// Security Implication: If DPoP validator accepts e=3, attacker can forge multiple
    /// proofs using low-exponent RSA and perform Coppersmith factorization offline.
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustReject_RsaKey_WithExponentE3()
    {
        // Arrange: Create RSA key with e=3 (weak)
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(includePrivateParameters: false);

        // Manually set exponent to 3 (0x03)
        parameters.Exponent = new byte[] { 0x03 };

        // Create proof with weak RSA key
        var proof = CreateDpopProofWithRsaKey(parameters, "RS256");

        var validator = CreateValidator();
        var request = new DpopValidationRequest(
            proof,
            "POST",
            new Uri("https://api.example.com/token"));

        // Act
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "RSA key with exponent e=3 is vulnerable to Coppersmith's Attack; must reject");
        result.Error.Should().Contain("weak", StringComparison.OrdinalIgnoreCase)
            .Or.Contain("invalid", StringComparison.OrdinalIgnoreCase)
            .Or.Contain("exponent", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Test: RSA key with exponent e=65535 (0xFFFF) MUST be rejected (just below FIPS threshold).
    ///
    /// FIPS 186-5 Requirement: e >= 65537 (0x010001)
    /// This test ensures we enforce the boundary, not just "some reasonable exponent."
    ///
    /// Security Implication: Off-by-one in exponent check creates vulnerability.
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustReject_RsaKey_WithExponentE65535()
    {
        // Arrange: Create RSA with e=65535 (just below 65537)
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(includePrivateParameters: false);

        // Exponent: 0xFFFF = 65535
        parameters.Exponent = new byte[] { 0xFF, 0xFF };

        var proof = CreateDpopProofWithRsaKey(parameters, "RS256");

        var validator = CreateValidator();
        var request = new DpopValidationRequest(
            proof,
            "POST",
            new Uri("https://api.example.com/token"));

        // Act
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "RSA exponent e < 65537 is below FIPS 186-5 requirement; must reject");
    }

    /// <summary>
    /// Test: RSA key with exponent e=65537 (0x010001) MUST be accepted (FIPS compliant).
    ///
    /// Verification that boundary is correct: e=65537 is the canonical "safe" exponent.
    /// Used by virtually all modern RSA keys (certificates, TLS, etc.).
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustAccept_RsaKey_WithExponentE65537()
    {
        // Arrange: Create RSA with e=65537 (standard, FIPS-approved)
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(includePrivateParameters: false);

        // Exponent: 0x010001 = 65537 (standard)
        parameters.Exponent = new byte[] { 0x01, 0x00, 0x01 };

        var proof = CreateDpopProofWithRsaKey(parameters, "RS256");

        var validator = CreateValidator();
        var request = new DpopValidationRequest(
            proof,
            "POST",
            new Uri("https://api.example.com/token"));

        // Act
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeTrue(
            "RSA with standard exponent e=65537 must be accepted");
    }

    /// <summary>
    /// Test: RSA key with modulus < 2048 bits MUST be rejected (FIPS 186-5).
    ///
    /// Background: 2048-bit RSA is the minimum for long-term security.
    /// 1024-bit RSA was broken in 2009; 1536-bit is academically broken.
    ///
    /// Security Implication: Accepting small RSA keys allows attacker to perform
    /// factorization attacks offline.
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustReject_RsaKey_With1024BitModulus()
    {
        // Arrange: Create 1024-bit RSA key (too small)
        using var rsa = RSA.Create(1024); // Weak!
        var parameters = rsa.ExportParameters(includePrivateParameters: false);

        var proof = CreateDpopProofWithRsaKey(parameters, "RS256");

        var validator = CreateValidator();
        var request = new DpopValidationRequest(
            proof,
            "POST",
            new Uri("https://api.example.com/token"));

        // Act
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "1024-bit RSA is too weak for modern security; must reject");
    }

    /// <summary>
    /// Test: EC key on non-approved curve (secp256k1) MUST be rejected.
    ///
    /// Background: secp256k1 is used in Bitcoin and cryptocurrency.
    /// However, FAPI 2.0 (and NIST) only approve: P-256, P-384, P-521.
    ///
    /// Security Implication: secp256k1 has different security properties and
    /// is not validated against backdoors/weaknesses that NIST curves undergo.
    /// Accepting it violates FAPI 2.0 compliance.
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustReject_EcKey_OnSecp256k1Curve()
    {
        // Arrange: Create EC key on secp256k1 (Bitcoin curve)
        // Note: .NET's ECDsa.Create may not directly support secp256k1 in older versions.
        // We'll simulate by creating a proof with invalid curve OID.

        var proof = CreateDpopProofWithUnapprovedCurve("secp256k1");

        var validator = CreateValidator();
        var request = new DpopValidationRequest(
            proof,
            "GET",
            new Uri("https://api.example.com/resource"));

        // Act
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "secp256k1 is not an approved curve for FAPI 2.0; must reject");
    }

    /// <summary>
    /// Test: EC key on approved curve (P-256) MUST be accepted.
    ///
    /// Verification that boundary is correct: P-256 is the standard for OAuth2.
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustAccept_EcKey_OnP256Curve()
    {
        // Arrange: Create EC key on P-256 (approved)
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecSecurityKey = new ECDsaSecurityKey(ec);

        var handler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new System.Security.Claims.ClaimsIdentity(),
            IssuedAt = DateTimeOffset.UtcNow.DateTime,
            Claims = new Dictionary<string, object>
            {
                ["htm"] = "GET",
                ["htu"] = "https://api.example.com/resource",
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["jti"] = Guid.NewGuid().ToString("N")
            },
            SigningCredentials = new SigningCredentials(
                ecSecurityKey,
                SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = "dpop+jwt"
            }
        };

        var proof = handler.CreateToken(tokenDescriptor);

        var validator = CreateValidator();
        var request = new DpopValidationRequest(
            proof,
            "GET",
            new Uri("https://api.example.com/resource"));

        // Act
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeTrue(
            "P-256 is an approved curve; must be accepted");
    }

    /// <summary>
    /// Test: RSA key with mismatched modulus and exponent (asymmetric corruption) MUST reject.
    ///
    /// Attack Scenario: Attacker provides RSA parameters where exponent and modulus
    /// don't correspond to a valid key (e.g., exponent from one key, modulus from another).
    ///
    /// Security Implication: ASN.1 parsing could succeed but key is mathematically invalid.
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustReject_RsaKey_WithMismatchedComponents()
    {
        // Arrange: Create first RSA key (exponent)
        using var rsa1 = RSA.Create(2048);
        var params1 = rsa1.ExportParameters(includePrivateParameters: false);

        // Create second RSA key (modulus)
        using var rsa2 = RSA.Create(2048);
        var params2 = rsa2.ExportParameters(includePrivateParameters: false);

        // Mix components (exponent from key1, modulus from key2)
        var corruptedParams = new RSAParameters
        {
            Modulus = params2.Modulus,
            Exponent = params1.Exponent // Mismatch!
        };

        var proof = CreateDpopProofWithRsaKey(corruptedParams, "RS256");

        var validator = CreateValidator();
        var request = new DpopValidationRequest(
            proof,
            "POST",
            new Uri("https://api.example.com/token"));

        // Act
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "RSA key with mismatched modulus and exponent must reject");
    }

    /// <summary>
    /// Test: Key with zero exponent MUST be rejected (mathematically invalid).
    ///
    /// Attack Scenario: Attacker provides e=0 hoping validator will accept it
    /// as a "benign mistake" or skip validation.
    ///
    /// Security Implication: e=0 is not a valid RSA exponent (breaks encryption/signing).
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustReject_RsaKey_WithZeroExponent()
    {
        // Arrange: Create RSA with e=0
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(includePrivateParameters: false);

        parameters.Exponent = new byte[] { 0x00 }; // Invalid!

        var proof = CreateDpopProofWithRsaKey(parameters, "RS256");

        var validator = CreateValidator();
        var request = new DpopValidationRequest(
            proof,
            "POST",
            new Uri("https://api.example.com/token"));

        // Act
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "RSA exponent e=0 is mathematically invalid; must reject");
    }

    /// <summary>
    /// Test: EC key with invalid point (not on curve) MUST be rejected.
    ///
    /// Attack Scenario: Attacker provides EC public key point that doesn't satisfy
    /// the curve equation (y^2 = x^3 + ax + b).
    ///
    /// Security Implication: Invalid points can lead to side-channel attacks or
    /// cryptographic failures.
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustReject_EcKey_WithInvalidPoint()
    {
        // Arrange: Create proof with EC point not on P-256 curve
        var proof = CreateDpopProofWithInvalidEcPoint();

        var validator = CreateValidator();
        var request = new DpopValidationRequest(
            proof,
            "GET",
            new Uri("https://api.example.com/resource"));

        // Act
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "EC public key point not on curve must be rejected");
    }

    // ============ Helpers ============

    private IDpopProofValidator CreateValidator()
    {
        var validatorType = Type.GetType(
            "Sentinel.DPoP.DpopProofValidator, Sentinel.DPoP",
            throwOnError: true)!;

        var instance = Activator.CreateInstance(
            validatorType,
            _mockReplayCache.Object,
            null,
            null)!;

        return (IDpopProofValidator)instance;
    }

    private static string CreateDpopProofWithRsaKey(RSAParameters rsaParams, string algorithm)
    {
        // Create RsaSecurityKey from parameters
        var rsa = RSA.Create(rsaParams);
        var rsaSecurityKey = new RsaSecurityKey(rsa);

        var handler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new System.Security.Claims.ClaimsIdentity(),
            IssuedAt = DateTimeOffset.UtcNow.DateTime,
            Claims = new Dictionary<string, object>
            {
                ["htm"] = "POST",
                ["htu"] = "https://api.example.com/token",
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["jti"] = Guid.NewGuid().ToString("N")
            },
            SigningCredentials = new SigningCredentials(rsaSecurityKey, algorithm),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = "dpop+jwt"
            }
        };

        return handler.CreateToken(tokenDescriptor);
    }

    private static string CreateDpopProofWithUnapprovedCurve(string curveName)
    {
        // Manually craft JWT with unapproved curve in header
        var header = JsonSerializer.Serialize(new
        {
            alg = "ES256",
            typ = "dpop+jwt",
            jwk = new
            {
                kty = "EC",
                crv = curveName, // Unapproved curve
                x = "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
                y = "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
            }
        });

        var payload = JsonSerializer.Serialize(new
        {
            htm = "GET",
            htu = "https://api.example.com/resource",
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            jti = Guid.NewGuid().ToString("N")
        });

        var headerB64 = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(header));
        var payloadB64 = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(payload));
        var signatureB64 = Base64UrlEncode(new byte[32]); // Dummy signature

        return $"{headerB64}.{payloadB64}.{signatureB64}";
    }

    private static string CreateDpopProofWithInvalidEcPoint()
    {
        // Manually craft JWT with EC point not on curve
        var header = JsonSerializer.Serialize(new
        {
            alg = "ES256",
            typ = "dpop+jwt",
            jwk = new
            {
                kty = "EC",
                crv = "P-256",
                x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // Invalid x
                y = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  // Invalid y
            }
        });

        var payload = JsonSerializer.Serialize(new
        {
            htm = "GET",
            htu = "https://api.example.com/resource",
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            jti = Guid.NewGuid().ToString("N")
        });

        var headerB64 = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(header));
        var payloadB64 = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(payload));
        var signatureB64 = Base64UrlEncode(new byte[64]); // Dummy signature

        return $"{headerB64}.{payloadB64}.{signatureB64}";
    }

    private static string Base64UrlEncode(byte[] data)
    {
        var base64 = Convert.ToBase64String(data);
        return base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
