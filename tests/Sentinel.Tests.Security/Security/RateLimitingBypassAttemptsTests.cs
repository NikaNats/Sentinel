using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Tests.Shared.Fixtures;

namespace Sentinel.Tests.Security;

[Collection("Sentinel Integration")]
public sealed class RateLimitingBypassAttemptsTests(SentinelApiFactory factory)
{
    private readonly HttpClient client = factory.CreateClient();

    [Fact]
    public async Task RepeatedRequests_WithSpoofedXForwardedForHeaders_DoNotBypassRateLimit()
    {
        var requestUrl = new Uri(client.BaseAddress!, "/v1/test/protected").ToString();

        var successCount = 0;
        var rateLimitedCount = 0;

        var tasks = Enumerable.Range(0, 200).Select(async i =>
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
            var token = TestTokenIssuer.MintAccessToken(jkt, subject: "rate-limit-user");
            using var request = CreateSignedRequest(ecdsa, jwkObject, token, HttpMethod.Get, requestUrl);
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", $"203.0.113.{i % 254 + 1}");

            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
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

        successCount.Should().BeLessThanOrEqualTo(102);
        rateLimitedCount.Should().BeGreaterThan(0);
    }

    private static HttpRequestMessage CreateSignedRequest(
        ECDsa signingKey,
        Dictionary<string, string> jwk,
        string accessToken,
        HttpMethod method,
        string requestUrl)
    {
        var securityKey = new ECDsaSecurityKey(signingKey) { KeyId = Guid.NewGuid().ToString("N") };
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = method.Method,
            ["htu"] = requestUrl,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = jwk }
        };

        var proof = new JsonWebTokenHandler().CreateToken(descriptor);
        var request = new HttpRequestMessage(method, requestUrl);
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
