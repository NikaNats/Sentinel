using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Sentinel.Infrastructure.Auth;
using Sentinel.Infrastructure.Auth.SdJwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sentinel.Tests.Unit;

public sealed class SdJwtVerifierTests
{
    [Fact]
    public async Task VerifyPresentationAsync_WhenDisclosureDigestNotAllowed_IgnoresClaim()
    {
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var sut = CreateVerifier(authorityKey);

        var allowedDisclosure = CreateDisclosure("salt-1", "name", "Visible Name");
        var ignoredDisclosure = CreateDisclosure("salt-2", "email", "hidden@example.com");
        var holderJwk = CreateEcJwkObject(holderKey);
        var holderJkt = ComputeEcThumbprint(holderJwk);
        var issuerJwt = CreateIssuerJwt(authorityKey, [ComputeDisclosureDigest(allowedDisclosure)], holderJkt);
        var kbJwt = CreateKeyBindingJwt(holderKey, holderJwk, issuerJwt, [allowedDisclosure, ignoredDisclosure], "sentinel-api", nonce: null);

        var result = await sut.VerifyPresentationAsync($"{issuerJwt}~{allowedDisclosure}~{ignoredDisclosure}~{kbJwt}", "sentinel-api", expectedNonce: null, CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Principal);
        Assert.Equal("Visible Name", result.Principal!.FindFirstValue("name"));
        Assert.Null(result.Principal.FindFirst("email"));
    }

    [Fact]
    public async Task VerifyPresentationAsync_WhenKeyBindingTokenIsStale_ReturnsFailure()
    {
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var sut = CreateVerifier(authorityKey, new SdJwtOptions { Enabled = true, KeyBindingMaxAgeSeconds = 60 });

        var disclosure = CreateDisclosure("salt-1", "name", "Visible Name");
        var holderJwk = CreateEcJwkObject(holderKey);
        var holderJkt = ComputeEcThumbprint(holderJwk);
        var issuerJwt = CreateIssuerJwt(authorityKey, [ComputeDisclosureDigest(disclosure)], holderJkt);
        var kbJwt = CreateKeyBindingJwt(
            holderKey,
            holderJwk,
            issuerJwt,
            [disclosure],
            "sentinel-api",
            nonce: null,
            issuedAt: DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds());

        var result = await sut.VerifyPresentationAsync($"{issuerJwt}~{disclosure}~{kbJwt}", "sentinel-api", expectedNonce: null, CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal("Key binding token is stale.", result.Error);
    }

    [Theory]
    [InlineData("md5")]
    [InlineData("sha1")]
    public async Task VerifyPresentationAsync_WhenHashAlgorithmUnsupported_ReturnsFailure(string hashAlgorithm)
    {
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var sut = CreateVerifier(authorityKey);

        var disclosure = CreateDisclosure("salt-1", "name", "Visible Name");
        var holderJwk = CreateEcJwkObject(holderKey);
        var holderJkt = ComputeEcThumbprint(holderJwk);
        var issuerJwt = CreateIssuerJwt(authorityKey, [ComputeDisclosureDigest(disclosure)], holderJkt, hashAlgorithm);
        var kbJwt = CreateKeyBindingJwt(holderKey, holderJwk, issuerJwt, [disclosure], "sentinel-api", nonce: null);

        var result = await sut.VerifyPresentationAsync($"{issuerJwt}~{disclosure}~{kbJwt}", "sentinel-api", expectedNonce: null, CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal($"Unsupported disclosure hash algorithm: {hashAlgorithm}", result.Error);
    }

    [Theory]
    [InlineData("not-a-presentation")]
    [InlineData("issuer~")]
    [InlineData("issuer~~kb")]
    public async Task VerifyPresentationAsync_WhenFormatMalformed_DoesNotThrow(string presentation)
    {
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var sut = CreateVerifier(authorityKey);

        var result = await sut.VerifyPresentationAsync(presentation, "sentinel-api", expectedNonce: null, CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Error);
    }

    private static SdJwtVerifier CreateVerifier(ECDsa authorityKey, SdJwtOptions? options = null)
    {
        var config = new OpenIdConnectConfiguration();
        config.SigningKeys.Add(new ECDsaSecurityKey(authorityKey));

        var configurationManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        configurationManager.Setup(x => x.GetConfigurationAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(config);

        return new SdJwtVerifier(
            Options.Create(new KeycloakOptions
            {
                Authority = "https://issuer.example",
                Audience = "sentinel-api",
                RequireHttpsMetadata = false
            }),
            Options.Create(options ?? new SdJwtOptions { Enabled = true }),
            configurationManager.Object,
            NullLogger<SdJwtVerifier>.Instance);
    }

    private static string CreateIssuerJwt(ECDsa authorityKey, string[] disclosureDigests, string holderJkt, string hashAlgorithm = "sha-256")
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "https://issuer.example",
            Audience = "sentinel-api",
            Claims = new Dictionary<string, object>
            {
                ["sub"] = "user-1",
                ["scope"] = "profile",
                ["acr"] = "acr2",
                ["_sd"] = disclosureDigests,
                ["_sd_alg"] = hashAlgorithm,
                ["cnf"] = new Dictionary<string, string> { ["jkt"] = holderJkt }
            },
            Expires = DateTimeOffset.UtcNow.AddMinutes(5).UtcDateTime,
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(authorityKey), SecurityAlgorithms.EcdsaSha256)
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static string CreateKeyBindingJwt(
        ECDsa holderKey,
        Dictionary<string, string> holderJwk,
        string issuerJwt,
        string[] disclosures,
        string audience,
        string? nonce,
        long? issuedAt = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["iat"] = issuedAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["sd_hash"] = ComputeSdHash(issuerJwt, disclosures)
        };

        if (!string.IsNullOrWhiteSpace(nonce))
        {
            claims["nonce"] = nonce;
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Audience = audience,
            Claims = claims,
            Expires = DateTimeOffset.UtcNow.AddMinutes(5).UtcDateTime,
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(holderKey), SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = holderJwk }
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static string CreateDisclosure(string salt, string claimName, string claimValue)
    {
        var json = JsonSerializer.Serialize(new object[] { salt, claimName, claimValue });
        return Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(json));
    }

    private static string ComputeDisclosureDigest(string disclosure)
    {
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(disclosure)));
    }

    private static string ComputeSdHash(string issuerJwt, string[] disclosures)
    {
        var presentationNoKb = $"{issuerJwt}~{string.Join("~", disclosures)}";
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(presentationNoKb)));
    }

    private static Dictionary<string, string> CreateEcJwkObject(ECDsa holderKey)
    {
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(holderKey));
        return new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };
    }

    private static string ComputeEcThumbprint(Dictionary<string, string> jwkObject)
    {
        var canonical = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["crv"] = jwkObject["crv"],
            ["kty"] = jwkObject["kty"],
            ["x"] = jwkObject["x"],
            ["y"] = jwkObject["y"]
        });

        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
