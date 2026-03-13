using Sentinel.Tests.Integration.Fixtures;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sentinel.Tests.Integration;

[Collection("Sentinel Integration")]
public sealed class AuthFlowIntegrationTests(SentinelApiFactory factory)
{
    private readonly HttpClient client = factory.CreateClient();

    [Fact]
    public async Task ProtectedEndpoint_WithoutToken_Returns401()
    {
        var response = await client.GetAsync("/v1/Profile");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task FullFapi2Flow_WithDpop_ReturnsProfile()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ecdsa));

        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };

        var canonical = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["crv"] = jwkObject["crv"],
            ["kty"] = jwkObject["kty"],
            ["x"] = jwkObject["x"],
            ["y"] = jwkObject["y"]
        });
        var jkt = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
        var accessToken = TestTokenIssuer.MintAccessToken(jkt);

        var requestUrl = new Uri(client.BaseAddress!, "/v1/profile").ToString();
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["htm"] = "GET",
                ["htu"] = requestUrl,
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = jwkObject
            }
        };
        var dpopProof = new JsonWebTokenHandler().CreateToken(descriptor);

        using var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        request.Headers.Add("DPoP", dpopProof);

        var response = await client.SendAsync(request);

        response.EnsureSuccessStatusCode();
        Assert.True(response.Headers.Contains("DPoP-Nonce"));
    }
}
