using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Sentinel.Infrastructure.Auth;
using Sentinel.Infrastructure.Auth.Ssf;

namespace Sentinel.Tests.Unit;

public sealed class JwtSsfTokenValidatorTests
{
    [Fact]
    public async Task ValidateAsync_WhenJtiMissing_ReturnsFailure()
    {
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var validator = CreateValidator(authorityKey);
        var set = CreateSetToken(authorityKey, claims =>
        {
            claims.Remove("jti");
            claims["events"] = CreateEventsPayload();
        });

        var result = await validator.ValidateAsync(set, CancellationToken.None);

        Assert.False(result.IsValid);
        Assert.Equal("SET missing required jti/iat.", result.Error);
    }

    [Fact]
    public async Task ValidateAsync_WhenEventsMissing_ReturnsFailure()
    {
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var validator = CreateValidator(authorityKey);
        var set = CreateSetToken(authorityKey, claims => claims.Remove("events"));

        var result = await validator.ValidateAsync(set, CancellationToken.None);

        Assert.False(result.IsValid);
        Assert.Equal("SET events claim is missing.", result.Error);
    }

    [Fact]
    public async Task ValidateAsync_WhenSignedByUnknownKey_ReturnsFailure()
    {
        using var trustedAuthority = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var validator = CreateValidator(trustedAuthority);
        var set = CreateSetToken(attackerKey, claims => claims["events"] = CreateEventsPayload());

        var result = await validator.ValidateAsync(set, CancellationToken.None);

        Assert.False(result.IsValid);
        Assert.Equal("SET is not a valid JWT.", result.Error);
    }

    [Fact]
    public async Task ValidateAsync_WhenSetIsTooOld_ReturnsFailure()
    {
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var validator = CreateValidator(authorityKey,
            new SsfOptions { MaxEventAgeSeconds = 60, AllowedClockSkewSeconds = 5 });
        var set = CreateSetToken(authorityKey, claims =>
        {
            claims["iat"] = DateTimeOffset.UtcNow.AddDays(-3).ToUnixTimeSeconds();
            claims["events"] = CreateEventsPayload();
        });

        var result = await validator.ValidateAsync(set, CancellationToken.None);

        Assert.False(result.IsValid);
        Assert.Equal("SET is too old.", result.Error);
    }

    private static JwtSsfTokenValidator CreateValidator(ECDsa authorityKey, SsfOptions? ssfOptions = null)
    {
        var config = new OpenIdConnectConfiguration();
        config.SigningKeys.Add(new ECDsaSecurityKey(authorityKey));

        var configurationManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        configurationManager.Setup(x => x.GetConfigurationAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(config);

        return new JwtSsfTokenValidator(
            Options.Create(new KeycloakOptions
            {
                Authority = "https://issuer.example",
                Audience = "sentinel-api",
                RequireHttpsMetadata = false
            }),
            Options.Create(ssfOptions ?? new SsfOptions()),
            configurationManager.Object,
            NullLogger<JwtSsfTokenValidator>.Instance);
    }

    private static string CreateSetToken(ECDsa signingKey, Action<Dictionary<string, object>>? mutateClaims = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-1",
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };
        mutateClaims?.Invoke(claims);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "https://issuer.example",
            Audience = "sentinel-api",
            Claims = claims,
            SigningCredentials =
                new SigningCredentials(new ECDsaSecurityKey(signingKey), SecurityAlgorithms.EcdsaSha256)
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static Dictionary<string, JsonElement> CreateEventsPayload()
    {
        return new Dictionary<string, JsonElement>
        {
            ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"] =
                JsonSerializer.SerializeToElement(new SessionRevokedPayload("sid-1", "user-1"))
        };
    }
}
