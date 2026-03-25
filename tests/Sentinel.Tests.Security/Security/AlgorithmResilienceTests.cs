using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Sentinel.DPoP;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Replay;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using Moq;
using Xunit;

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
/// </summary>
public sealed class AlgorithmResilienceTests
{
    private readonly Mock<IJtiReplayCache> _replayCache;

    public AlgorithmResilienceTests()
    {
        _replayCache = new Mock<IJtiReplayCache>();
        _replayCache
            .Setup(x => x.TryMarkUsedAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
    }

    /// <summary>
    /// Test: Proof with EC key (P-256) claiming RS256 (RSA algorithm) MUST be rejected.
    ///
    /// Attack Scenario: Attacker has EC key from legitimate registration.
    /// Attacker forges proof header claiming "alg": "RS256" (RSA).
    /// If validator accepts this mismatch, the signature verification logic
    /// might use EC math to verify RSA signatures, leading to bypass.
    ///
    /// Security Invariant: Algorithm claimed in JWT header MUST match key type.
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustReject_AlgorithmKeyTypeMismatch_EC_To_RS()
    {
        // Arrange: Generate valid EC key
        using var ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecSecurityKey = new ECDsaSecurityKey(ecKey);

        // Create malicious proof: Header claims RS256 but uses EC key
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
            // Attack: Claim RS256 (RSA) but sign with EC key
            SigningCredentials = new SigningCredentials(
                ecSecurityKey,
                SecurityAlgorithms.RsaSsaPssSha256), // Mismatch!
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = "dpop+jwt"
            }
        };

        var malformedProof = handler.CreateToken(tokenDescriptor);
        var request = new DpopValidationRequest(
            malformedProof,
            "POST",
            new Uri("https://api.example.com/token"));

        // Act
        var validator = CreateValidator();
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "DPoP validator must reject proofs where algorithm header does not match key type");
    }

    /// <summary>
    /// Test: Proof claiming unsupported algorithm (e.g., HMAC HS256) MUST be rejected.
    ///
    /// Attack Scenario: Attacker attempts to bypass signature verification
    /// by using symmetric HMAC instead of asymmetric RSA/EC.
    /// If validator uses the JWK as HMAC secret, attacker can forge proofs.
    ///
    /// Security Invariant: Only asymmetric algorithms allowed (ES256, PS256, EdDSA, MLDSA*).
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustReject_SymmetricAlgorithm_HS256()
    {
        // Arrange: Proof claiming HS256 (HMAC)
        using var ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecSecurityKey = new ECDsaSecurityKey(ecKey);

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
                SecurityAlgorithms.HmacSha256), // Attack: symmetric crypto
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = "dpop+jwt"
            }
        };

        var malformedProof = handler.CreateToken(tokenDescriptor);
        var request = new DpopValidationRequest(
            malformedProof,
            "GET",
            new Uri("https://api.example.com/resource"));

        // Act
        var validator = CreateValidator();
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "Symmetric algorithms (HMAC) are not allowed in DPoP; must be asymmetric");
    }

    /// <summary>
    /// Test: Proof claiming "alg: none" MUST be rejected.
    ///
    /// Attack Scenario: Attacker forges proof with no signature verification required.
    /// Classic "alg: none" bypass from JWT vulnerabilities.
    ///
    /// Security Invariant: Every DPoP proof must be cryptographically signed.
    /// No exceptions, ever.
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustReject_AlgorithmNone()
    {
        // Arrange: Manually craft a JWT with "alg": "none"
        var header = JsonSerializer.Serialize(new { alg = "none", typ = "dpop+jwt" });
        var payload = JsonSerializer.Serialize(new
        {
            htm = "GET",
            htu = "https://api.example.com/resource",
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            jti = Guid.NewGuid().ToString("N")
        });

        var headerB64 = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(header));
        var payloadB64 = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(payload));
        var signatureB64 = ""; // No signature

        var unsignedProof = $"{headerB64}.{payloadB64}.{signatureB64}";

        var request = new DpopValidationRequest(
            unsignedProof,
            "GET",
            new Uri("https://api.example.com/resource"));

        // Act
        var validator = CreateValidator();
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "DPoP validator must reject proofs with 'alg: none'");
    }

    /// <summary>
    /// Test: RSA key with ES256 (ECDSA) claim MUST be rejected.
    ///
    /// Attack Scenario: Attacker has RSA key but claims ES256 signature.
    /// Reverse scenario from EC-to-RS test.
    ///
    /// Security Invariant: Bidirectional enforcement of algorithm-key binding.
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustReject_AlgorithmKeyTypeMismatch_RS_To_EC()
    {
        // Arrange: Generate RSA key
        using var rsa = RSA.Create(2048);
        var rsaSecurityKey = new RsaSecurityKey(rsa);

        var handler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new System.Security.Claims.ClaimsIdentity(),
            IssuedAt = DateTimeOffset.UtcNow.DateTime,
            Claims = new Dictionary<string, object>
            {
                ["htm"] = "DELETE",
                ["htu"] = "https://api.example.com/resource/123",
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["jti"] = Guid.NewGuid().ToString("N")
            },
            // Attack: Claim ES256 (ECDSA) but use RSA key
            SigningCredentials = new SigningCredentials(
                rsaSecurityKey,
                SecurityAlgorithms.EcdsaSha256), // Mismatch!
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = "dpop+jwt"
            }
        };

        var malformedProof = handler.CreateToken(tokenDescriptor);
        var request = new DpopValidationRequest(
            malformedProof,
            "DELETE",
            new Uri("https://api.example.com/resource/123"));

        // Act
        var validator = CreateValidator();
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "RSA key cannot produce ES256 signatures; mismatch must be caught");
    }

    /// <summary>
    /// Test: Proof with invalid JWK structure (missing required fields) MUST be rejected.
    ///
    /// Attack Scenario: Attacker provides incomplete JWK without "kty", "crv", or "x" fields.
    /// Validator must not crash or make assumptions; must fail safely.
    ///
    /// Security Invariant: All JWK fields must be present and valid before any verification.
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustReject_InvalidJwkStructure()
    {
        // Arrange: Create proof with minimal/invalid JWK
        using var ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecSecurityKey = new ECDsaSecurityKey(ecKey);

        var handler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new System.Security.Claims.ClaimsIdentity(),
            IssuedAt = DateTimeOffset.UtcNow.DateTime,
            Claims = new Dictionary<string, object>
            {
                ["htm"] = "POST",
                ["htu"] = "https://api.example.com/auth",
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["jti"] = Guid.NewGuid().ToString("N")
            },
            SigningCredentials = new SigningCredentials(ecSecurityKey, SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = "dpop+jwt",
                ["jwk"] = new { } // Empty/incomplete JWK
            }
        };

        var invalidProof = handler.CreateToken(tokenDescriptor);
        var request = new DpopValidationRequest(
            invalidProof,
            "POST",
            new Uri("https://api.example.com/auth"));

        // Act
        var validator = CreateValidator();
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "Proof with incomplete JWK structure must be rejected");
    }

    /// <summary>
    /// Test: Proof containing private key in JWK MUST be rejected (never trusted).
    ///
    /// Attack Scenario: Attacker includes private key in JWK hoping for extraction.
    /// Validator must explicitly reject any JWK with private key material.
    ///
    /// Security Invariant: Only public keys accepted; private keys indicate compromise.
    /// </summary>
    [Fact]
    public async Task DpopValidator_MustReject_JwkContainingPrivateKey()
    {
        // Arrange: Create proof with private key included (d parameter)
        using var ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecSecurityKey = new ECDsaSecurityKey(ecKey);

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
            SigningCredentials = new SigningCredentials(ecSecurityKey, SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = "dpop+jwt",
                ["jwk"] = new
                {
                    kty = "EC",
                    crv = "P-256",
                    x = "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
                    y = "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
                    d = "private_key_material_here" // Attack: includes private key!
                }
            }
        };

        var proofWithPrivateKey = handler.CreateToken(tokenDescriptor);
        var request = new DpopValidationRequest(
            proofWithPrivateKey,
            "POST",
            new Uri("https://api.example.com/token"));

        // Act
        var validator = CreateValidator();
        var result = await validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "Proof with private key in JWK must be rejected as potential compromise");
    }

    /// <summary>
    /// Helper: Creates DpopProofValidator via reflection (internal class).
    /// </summary>
    private IDpopProofValidator CreateValidator()
    {
        var validatorType = Type.GetType(
            "Sentinel.DPoP.DpopProofValidator, Sentinel.DPoP",
            throwOnError: true)!;

        var instance = Activator.CreateInstance(
            validatorType,
            _replayCache.Object,
            null,
            null)!;

        return (IDpopProofValidator)instance;
    }

    /// <summary>
    /// Helper: Base64Url encodes a byte array per RFC 4648 Section 5.
    /// </summary>
    private static string Base64UrlEncode(byte[] data)
    {
        var base64 = Convert.ToBase64String(data);
        return base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
