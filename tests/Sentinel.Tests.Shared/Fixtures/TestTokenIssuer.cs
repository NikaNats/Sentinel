using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.Tests.Shared.Fixtures;

public static class TestTokenIssuer
{
    public static readonly ECDsa AuthorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public static readonly ECDsaSecurityKey AuthoritySecurityKey = new(AuthorityKey) { KeyId = "test-authority-key" };

    public static string MintAccessToken(
        string jkt,
        string acr = "acr3",
        string scope = "profile",
        string issuer = "https://localhost:8443/realms/sentinel",
        string audience = "sentinel-api",
        int expiresInSeconds = 300,
        string? subject = null,
        string? sid = null)
    {
        var handler = new JsonWebTokenHandler();
        var now = DateTimeOffset.UtcNow;
        var exp = now.AddSeconds(expiresInSeconds);

        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Sub] = subject ?? Guid.NewGuid().ToString(),
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            [JwtRegisteredClaimNames.Iat] = now.ToUnixTimeSeconds(),
            [JwtRegisteredClaimNames.Exp] = exp.ToUnixTimeSeconds(),
            ["acr"] = acr,
            ["scope"] = scope,
            ["realm_access.roles"] = JsonSerializer.Serialize(new[] { "user" }),
            ["cnf"] = new Dictionary<string, string> { ["jkt"] = jkt }
        };

        if (!string.IsNullOrWhiteSpace(sid))
        {
            claims["sid"] = sid;
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Claims = claims,
            Expires = exp.UtcDateTime,
            SigningCredentials = new SigningCredentials(AuthoritySecurityKey, SecurityAlgorithms.EcdsaSha256)
        };

        return handler.CreateToken(descriptor);
    }
}
