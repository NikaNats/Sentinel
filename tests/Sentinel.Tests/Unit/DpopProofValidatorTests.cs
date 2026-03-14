using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Auth;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sentinel.Tests.Unit;

public sealed class DpopProofValidatorTests
{
    private readonly Mock<IJtiReplayCache> replayCache = new();

    public DpopProofValidatorTests()
    {
        replayCache
            .Setup(x => x.ExistsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(ValueTask.FromResult(false));
    }

    [Fact]
    public async Task ValidateAsync_WithValidProof_ReturnsSuccess()
    {
        var sut = new DpopProofValidator(replayCache.Object);
        var (dpopProof, accessToken) = CreateValidProofAndToken("POST", "https://localhost/v1/profile");

        var result = await sut.ValidateAsync(dpopProof, accessToken, "POST", "https://localhost/v1/profile", CancellationToken.None);

        Assert.True(result.IsValid);
        Assert.NotEmpty(result.NewNonce);
    }

    [Fact]
    public async Task ValidateAsync_WithReplayedJti_ReturnsInvalid()
    {
        replayCache
            .Setup(x => x.ExistsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(ValueTask.FromResult(true));

        var sut = new DpopProofValidator(replayCache.Object);
        var (dpopProof, accessToken) = CreateValidProofAndToken("POST", "https://localhost/v1/profile");

        var result = await sut.ValidateAsync(dpopProof, accessToken, "POST", "https://localhost/v1/profile", CancellationToken.None);

        Assert.False(result.IsValid);
    }

    private static (string DpopProof, string AccessToken) CreateValidProofAndToken(string method, string url)
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

        var dpopDescriptor = new SecurityTokenDescriptor
        {
            Issuer = "client",
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["htm"] = method,
                ["htu"] = url,
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            },
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
