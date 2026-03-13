using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Tests.Integration.Fixtures;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sentinel.Tests.Integration;

[Collection("Sentinel Integration")]
public sealed class SecurityScenarioTests(SentinelApiFactory factory)
{
    private readonly HttpClient client = factory.CreateClient();

    [Fact(Skip = "Requires Docker-backed Keycloak/Redis integration environment.")]
    public async Task S05_AttackerInjectsRS256DpopProof_Returns401()
    {
        var accessToken = CreateUnsignedAccessToken("placeholder-thumbprint");

        using var rsa = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa);
        var rsaJwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaKey);
        var handler = new JsonWebTokenHandler();

        var proofDescriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["htm"] = "GET",
                ["htu"] = $"{client.BaseAddress}v1/Profile",
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            },
            SigningCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = new Dictionary<string, string>
                {
                    ["kty"] = rsaJwk.Kty!,
                    ["n"] = rsaJwk.N!,
                    ["e"] = rsaJwk.E!
                }
            }
        };

        var maliciousProof = handler.CreateToken(proofDescriptor);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/Profile");
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        request.Headers.Add("DPoP", maliciousProof);

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("invalid_dpop_proof", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact(Skip = "Requires Docker-backed Keycloak/Redis integration environment.")]
    public async Task S14_AttackerReplaysTokenWithDifferentKey_Returns401()
    {
        using var originalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var originalJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(originalKey));
        var originalThumbprint = ComputeEcThumbprint(originalJwk);

        var stolenAccessToken = CreateUnsignedAccessToken(originalThumbprint);

        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var attackerSecurityKey = new ECDsaSecurityKey(attackerKey) { KeyId = Guid.NewGuid().ToString("N") };
        var attackerJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(attackerSecurityKey);
        var handler = new JsonWebTokenHandler();

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["htm"] = "GET",
                ["htu"] = $"{client.BaseAddress}v1/Profile",
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            },
            SigningCredentials = new SigningCredentials(attackerSecurityKey, SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = new Dictionary<string, string>
                {
                    ["kty"] = attackerJwk.Kty!,
                    ["crv"] = attackerJwk.Crv!,
                    ["x"] = attackerJwk.X!,
                    ["y"] = attackerJwk.Y!
                }
            }
        };

        var attackerProof = handler.CreateToken(descriptor);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/Profile");
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", stolenAccessToken);
        request.Headers.Add("DPoP", attackerProof);

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("invalid_dpop_proof", response.Headers.WwwAuthenticate.ToString());
    }

    private static string CreateUnsignedAccessToken(string jkt)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["cnf"] = new Dictionary<string, string> { ["jkt"] = jkt }
            }
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static string ComputeEcThumbprint(JsonWebKey jwk)
    {
        var canonical = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        });

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncoder.Encode(hash);
    }
}
