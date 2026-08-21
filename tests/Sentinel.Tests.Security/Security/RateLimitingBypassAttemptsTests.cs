using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Tests.Shared;

namespace Sentinel.Tests.Security;

[Collection("Sentinel Integration")]
public sealed class RateLimitingBypassAttemptsTests(SentinelApiFactory factory)
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact(DisplayName =
        "🛡️ Rate Limiting: Spoofed X-Forwarded-For headers with same user token MUST NOT bypass rate limit (Permit=20, Queue=5 -> Max 25 Success)")]
    public async Task RepeatedRequests_WithSpoofedXForwardedForHeaders_DoNotBypassRateLimit()
    {
        var requestUrl = new Uri(_client.BaseAddress!, "/v1/test/protected").ToString();

        var successCount = 0;
        var rateLimitedCount = 0;
        var totalRequests = 200;

        // 200 concurrent requests from the same identity (sub: rate-limit-user),
        // each presenting a different spoofed source IP via X-Forwarded-For.
        var tasks = Enumerable.Range(0, totalRequests).Select(async i =>
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

            // Attempt to evade the rate limiter by rotating source IPs.
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", $"203.0.113.{i % 254 + 1}");

            using var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

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

        // 1. The identity partition (sub:rate-limit-user) must cap the user:
        //    20 permits (PermitLimit) + 5 queued (QueueLimit) = at most 25 successes.
        successCount.Should().BeLessThanOrEqualTo(25,
            "Authenticated users must not bypass rate limits by rotating IP addresses. Identity partitioning must restrict them to permit + queue limit.");

        // 2. Requests exceeding the identity quota must be throttled with HTTP 429.
        rateLimitedCount.Should().BeGreaterThan(0,
            "Requests exceeding the identity quota must be throttled with HTTP 429.");

        // 3. Every request must either succeed within quota or be throttled - no 5xx leaks.
        (successCount + rateLimitedCount).Should().Be(totalRequests,
            "Every request must either succeed within quota or fail with 429 (no 500 errors).");
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
            ["crv"] = jwk["crv"] ?? "P-256",
            ["kty"] = jwk["kty"] ?? "EC",
            ["x"] = jwk["x"]!,
            ["y"] = jwk["y"]!
        }, TestJsonContext.Default.DictionaryStringString);

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncoder.Encode(hash);
    }
}
