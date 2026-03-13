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

    [Fact]
    public async Task S01_ExpiredAccessToken_Returns401()
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

        var jkt = ComputeEcThumbprint(jwkObject);
        var expiredToken = TestTokenIssuer.MintAccessToken(jkt, expiresInSeconds: -5);
        var requestUrl = new Uri(client.BaseAddress!, "/v1/profile").ToString();
        using var request = CreateSignedRequest(ecdsa, jwkObject, expiredToken, HttpMethod.Get, requestUrl);

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task S14_AttackerReplaysTokenWithDifferentKey_Returns401()
    {
        using var originalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var originalJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(originalKey));
        var originalJwkObject = new Dictionary<string, string>
        {
            ["crv"] = originalJwk.Crv!,
            ["kty"] = originalJwk.Kty!,
            ["x"] = originalJwk.X!,
            ["y"] = originalJwk.Y!
        };
        var originalThumbprint = ComputeEcThumbprint(originalJwkObject);

        var stolenAccessToken = TestTokenIssuer.MintAccessToken(originalThumbprint);

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

    [Fact]
    public async Task S03_ReplayedJti_IsCaughtByReplayCache_Returns401()
    {
        var requestUri = new Uri(client.BaseAddress!, "/v1/profile");
        var requestUrl = requestUri.ToString();

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
        var jkt = ComputeEcThumbprint(jwkObject);

        var accessToken1 = TestTokenIssuer.MintAccessToken(jkt);
        var accessToken2 = TestTokenIssuer.MintAccessToken(jkt);

        var proofJti = Guid.NewGuid().ToString("N");
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = proofJti,
                ["htm"] = "GET",
                ["htu"] = requestUrl,
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            },
            SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = jwkObject
            }
        };
        var proof = new JsonWebTokenHandler().CreateToken(descriptor);

        using var req1 = new HttpRequestMessage(HttpMethod.Get, requestUri);
        req1.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken1);
        req1.Headers.Add("DPoP", proof);
        var res1 = await client.SendAsync(req1);
        Assert.Equal(HttpStatusCode.OK, res1.StatusCode);

        using var req2 = new HttpRequestMessage(HttpMethod.Get, requestUri);
        req2.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken2);
        req2.Headers.Add("DPoP", proof);
        var res2 = await client.SendAsync(req2);
        Assert.Equal(HttpStatusCode.Unauthorized, res2.StatusCode);
    }

    [Fact]
    public async Task S10_InvalidAudience_Returns401()
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

        var jkt = ComputeEcThumbprint(jwkObject);
        var badAudienceToken = TestTokenIssuer.MintAccessToken(jkt, audience: "some-other-api");
        var requestUrl = new Uri(client.BaseAddress!, "/v1/profile").ToString();
        using var request = CreateSignedRequest(ecdsa, jwkObject, badAudienceToken, HttpMethod.Get, requestUrl);

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task S11_MissingScope_Returns403()
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

        var jkt = ComputeEcThumbprint(jwkObject);
        var noScopeToken = TestTokenIssuer.MintAccessToken(jkt, scope: "email");
        var requestUrl = new Uri(client.BaseAddress!, "/v1/profile").ToString();
        using var request = CreateSignedRequest(ecdsa, jwkObject, noScopeToken, HttpMethod.Get, requestUrl);

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task S07_RateLimitExceeded_Returns429()
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
        var jkt = ComputeEcThumbprint(jwkObject);

        var successCount = 0;
        var rateLimitedCount = 0;
        var requestUrl = new Uri(client.BaseAddress!, "/v1/profile").ToString();

        var tasks = Enumerable.Range(0, 105).Select(async _ =>
        {
            var accessToken = TestTokenIssuer.MintAccessToken(jkt);
            using var request = CreateSignedRequest(ecdsa, jwkObject, accessToken, HttpMethod.Get, requestUrl);
            var response = await client.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                Interlocked.Increment(ref successCount);
            }
            else if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                Interlocked.Increment(ref rateLimitedCount);
            }
        });

        await Task.WhenAll(tasks);

        Assert.True(successCount <= 102, $"Expected at most 102 successful requests (100 permits + queue of 2), but got {successCount}");
        Assert.True(rateLimitedCount > 0, "Expected at least one 429 TooManyRequests response.");
    }

    private static HttpRequestMessage CreateSignedRequest(ECDsa ecdsa, Dictionary<string, string> jwkObject, string accessToken, HttpMethod method, string url)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["htm"] = method.Method,
                ["htu"] = url,
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = jwkObject
            }
        };

        var proof = new JsonWebTokenHandler().CreateToken(descriptor);

        var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        request.Headers.Add("DPoP", proof);
        return request;
    }

    private static string ComputeEcThumbprint(Dictionary<string, string> jwk)
    {
        var canonical = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["crv"] = jwk["crv"],
            ["kty"] = jwk["kty"],
            ["x"] = jwk["x"],
            ["y"] = jwk["y"]
        });

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncoder.Encode(hash);
    }
}
