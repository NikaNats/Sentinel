using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Sentinel.DPoP;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Tests.Shared;

namespace Sentinel.Tests.Security.Security;

public sealed class WeakKeyTests
{
    private readonly Mock<IJtiReplayCache> _replayCacheMock = new();

    public WeakKeyTests()
    {
        _replayCacheMock
            .Setup(x => x.TryMarkUsedAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
    }

    [Fact]
    public async Task DpopValidatorMustRejectAlgorithmNoneProof()
    {
        var proof =
            "eyJhbGciOiJub25lIiwidHlwIjoiZHBvcCtqd3QifQ.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20vdG9rZW4iLCJpYXQiOjE3MDAwMDAwMDAsImp0aSI6InQifQ.";
        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.example.com/token"));

        var result = await CreateValidator().ValidateAsync(request);

        result.IsSuccess.Should().BeFalse();
    }

    [Fact]
    public async Task DpopValidatorMustRejectRsaAlgorithmProof()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proof = TestJwtBuilder.CreateMalformedProof(ec, SecurityAlgorithms.RsaSha256, "RSA");
        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.example.com/token"));

        var result = await CreateValidator().ValidateAsync(request);

        result.IsSuccess.Should().BeFalse();
    }

    [Fact]
    public async Task DpopValidatorMustAcceptValidEs256Proof()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new ECDsaSecurityKey(ec);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["htm"] = "GET",
                ["htu"] = "https://api.example.com/resource",
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            },
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = "dpop+jwt",
                ["jwk"] = new Dictionary<string, string>
                {
                    ["kty"] = jwk.Kty!,
                    ["crv"] = jwk.Crv!,
                    ["x"] = jwk.X!,
                    ["y"] = jwk.Y!
                }
            }
        };

        var handler = new JwtSecurityTokenHandler();
        var proof = handler.WriteToken(handler.CreateToken(descriptor));
        var request = new DpopValidationRequest(proof, "GET", new Uri("https://api.example.com/resource"));

        var result = await CreateValidator().ValidateAsync(request);

        result.IsSuccess.Should().BeTrue();
    }

    private DpopProofValidator CreateValidator()
    {
        var options = Options.Create(new DPoPOptions());
        return new DpopProofValidator(_replayCacheMock.Object, options, null, TimeProvider.System);
    }
}
