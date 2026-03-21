using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Auth;

namespace Sentinel.Tests.Unit;

public sealed class DpopProofValidatorTests
{
    private readonly Mock<IJtiReplayCache> replayCache = new();

    public DpopProofValidatorTests()
    {
        replayCache
            .Setup(x => x.TryStoreIfNotExistsAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
    }

    [Fact]
    public async Task ValidateAsync_WithValidProof_ReturnsSuccess()
    {
        var sut = new DpopProofValidator(replayCache.Object);
        var (dpopProof, accessToken) = CreateValidProofAndToken("POST", "https://localhost/v1/profile");

        var result = await sut.ValidateAsync(dpopProof, accessToken, "POST", "https://localhost/v1/profile", null,
            CancellationToken.None);

        Assert.True(result.IsValid);
        Assert.NotEmpty(result.NewNonce);
    }

    [Fact]
    public async Task ValidateAsync_WithReplayedJti_ReturnsInvalid()
    {
        replayCache
            .Setup(x => x.TryStoreIfNotExistsAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var sut = new DpopProofValidator(replayCache.Object);
        var (dpopProof, accessToken) = CreateValidProofAndToken("POST", "https://localhost/v1/profile");

        var result = await sut.ValidateAsync(dpopProof, accessToken, "POST", "https://localhost/v1/profile", null,
            CancellationToken.None);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task ValidateAsync_WhenExpectedNonceIsMissing_ReturnsUseDpopNonceError()
    {
        var sut = new DpopProofValidator(replayCache.Object);
        var (dpopProof, accessToken) = CreateValidProofAndToken("POST", "https://localhost/v1/profile", null);

        var result = await sut.ValidateAsync(dpopProof, accessToken, "POST", "https://localhost/v1/profile",
            "expected-nonce", CancellationToken.None);

        Assert.False(result.IsValid);
        Assert.Equal("use_dpop_nonce", result.Error);
    }

    [Theory]
    [InlineData("MLDSA44")]
    [InlineData("MLDSA65")]
    [InlineData("MLDSA87")]
    [InlineData(SecurityAlgorithms.EcdsaSha256)]
    [InlineData(SecurityAlgorithms.RsaSsaPssSha256)]
    public void IsSupportedAlgorithm_WhenKnownAlgorithm_ReturnsTrue(string algorithm)
    {
        var supported = DpopProofValidator.IsSupportedAlgorithm(algorithm);

        Assert.True(supported);
    }

    [Theory]
    [InlineData("HS256")]
    [InlineData("")]
    [InlineData(null)]
    public void IsSupportedAlgorithm_WhenUnknownOrEmpty_ReturnsFalse(string? algorithm)
    {
        var supported = DpopProofValidator.IsSupportedAlgorithm(algorithm);

        Assert.False(supported);
    }

    [Fact]
    public async Task ValidateAsync_WhenUnsupportedAlgorithm_ReturnsInvalidWithoutReplayCacheWrite()
    {
        var sut = new DpopProofValidator(replayCache.Object);
        const string dpopHeader =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJqdGkiOiJhYmMiLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9sb2NhbGhvc3QvdjEvcHJvZmlsZSIsImlhdCI6MTcxMDAwMDAwMH0.signature";
        const string accessToken = "eyJhbGciOiJub25lIn0.eyJjbmYiOnsiamt0IjoiYWJjIn19.";

        var result = await sut.ValidateAsync(dpopHeader, accessToken, "POST", "https://localhost/v1/profile", null,
            CancellationToken.None);

        Assert.False(result.IsValid);
        replayCache.Verify(
            x => x.TryStoreIfNotExistsAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    private static (string DpopProof, string AccessToken) CreateValidProofAndToken(string method, string url,
        string? nonce = null)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var securityKey = new ECDsaSecurityKey(ecdsa) { KeyId = Guid.NewGuid().ToString("N") };
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(securityKey);

        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };

        var jkt = ComputeThumbprint(jwkObject);
        var handler = new JsonWebTokenHandler();

        var dpopClaims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = method,
            ["htu"] = url,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        if (!string.IsNullOrWhiteSpace(nonce))
        {
            dpopClaims["nonce"] = nonce;
        }

        var dpopDescriptor = new SecurityTokenDescriptor
        {
            Issuer = "client",
            Claims = dpopClaims,
            SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = jwkObject
            }
        };

        var accessDescriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["cnf"] = new Dictionary<string, string> { ["jkt"] = jkt }
            }
        };

        return (handler.CreateToken(dpopDescriptor), handler.CreateToken(accessDescriptor));
    }

    private static string ComputeThumbprint(Dictionary<string, string> jwkObject)
    {
        var canonical = JsonSerializer.Serialize(jwkObject);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncoder.Encode(hash);
    }
}
