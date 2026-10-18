using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Sentinel.AspNetCore.Ssf;

namespace Sentinel.Tests.Unit.Unit;

public sealed class JwksSsfTokenValidatorTests : IDisposable
{
    private const string Issuer = "https://idp.example.test/realms/sentinel";
    private const string Audience = "sentinel-api";
    private const string SessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

    private readonly ECDsa _issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public void Dispose()
    {
        _issuerKey.Dispose();
        _attackerKey.Dispose();
    }

    [Fact(DisplayName = "✅ SET: valid signature, issuer and audience yields events")]
    public async Task ValidSet_Succeeds()
    {
        var result = await CreateValidator().ValidateAsync(Sign(_issuerKey, Issuer), TestContext.Current.CancellationToken);

        result.IsValid.Should().BeTrue();
        result.Token!.Events.Should().ContainKey(SessionRevoked);
        result.Token.Subject.Should().Be("user-1");
    }

    [Fact(DisplayName = "🔴 SET: signature from a key outside the JWKS is rejected without leaking details")]
    public async Task ForeignKey_IsRejectedGenerically()
    {
        var result = await CreateValidator().ValidateAsync(Sign(_attackerKey, Issuer), TestContext.Current.CancellationToken);

        result.IsValid.Should().BeFalse();
        result.Error.Should().Be("SET signature or claims validation failed.");
    }

    [Fact(DisplayName = "🔴 SET: wrong issuer is rejected")]
    public async Task WrongIssuer_IsRejected()
    {
        var result = await CreateValidator().ValidateAsync(Sign(_issuerKey, "https://evil.example.test"),
            TestContext.Current.CancellationToken);

        result.IsValid.Should().BeFalse();
        result.Error.Should().NotContain("IDX");
    }

    [Fact(DisplayName = "🔴 SET: token without an events object is rejected")]
    public async Task MissingEvents_IsRejected()
    {
        var result = await CreateValidator().ValidateAsync(Sign(_issuerKey, Issuer, includeEvents: false),
            TestContext.Current.CancellationToken);

        result.IsValid.Should().BeFalse();
    }

    private JwksSsfTokenValidator CreateValidator()
    {
        var config = new OpenIdConnectConfiguration();
        config.SigningKeys.Add(new ECDsaSecurityKey(_issuerKey) { KeyId = "issuer-key" });
        return new JwksSsfTokenValidator(Issuer, Audience,
            new FixedConfigurationManager(config),
            NullLogger<JwksSsfTokenValidator>.Instance);
    }

    private static string Sign(ECDsa key, string issuer, bool includeEvents = true)
    {
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["sub"] = "user-1",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };
        if (includeEvents)
        {
            claims["events"] = new Dictionary<string, object> { [SessionRevoked] = new Dictionary<string, object>() };
        }

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = Audience,
            Claims = claims,
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key) { KeyId = "issuer-key" },
                SecurityAlgorithms.EcdsaSha256)
        });
    }

    private sealed class FixedConfigurationManager(OpenIdConnectConfiguration config)
        : IConfigurationManager<OpenIdConnectConfiguration>
    {
        public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel) => Task.FromResult(config);

        public void RequestRefresh()
        {
        }
    }
}
