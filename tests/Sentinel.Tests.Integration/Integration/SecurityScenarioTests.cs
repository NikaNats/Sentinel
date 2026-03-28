using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

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
        var requestUrl = new Uri(client.BaseAddress!, "/v1/test/protected").ToString();
        using var request = CreateSignedRequest(ecdsa, jwkObject, expiredToken, HttpMethod.Get, requestUrl);

        var response = await client.SendAsync(request, CancellationToken.None);

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

        var response = await client.SendAsync(request, CancellationToken.None);

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
        var firstProof = CreateDpopProof(securityKey, jwkObject, proofJti, requestUrl, null);

        using var req1 = new HttpRequestMessage(HttpMethod.Get, requestUri);
        req1.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken1);
        req1.Headers.Add("DPoP", firstProof);
        var res1 = await client.SendAsync(req1, CancellationToken.None);
        Assert.Equal(HttpStatusCode.OK, res1.StatusCode);

        Assert.True(res1.Headers.TryGetValues("DPoP-Nonce", out var nonceValues));
        var nonce = nonceValues!.First();
        var replayProofWithNonce = CreateDpopProof(securityKey, jwkObject, proofJti, requestUrl, nonce);

        using var req2 = new HttpRequestMessage(HttpMethod.Get, requestUri);
        req2.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken2);
        req2.Headers.Add("DPoP", replayProofWithNonce);
        var res2 = await client.SendAsync(req2, CancellationToken.None);
        Assert.Equal(HttpStatusCode.Unauthorized, res2.StatusCode);
        Assert.Contains("invalid_dpop_proof", res2.Headers.WwwAuthenticate.ToString());
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

        var response = await client.SendAsync(request, CancellationToken.None);

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

        var response = await client.SendAsync(request, CancellationToken.None);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task S07_RateLimitExceeded_Returns429()
    {
        var successCount = 0;
        var rateLimitedCount = 0;
        var requestUrl = new Uri(client.BaseAddress!, "/v1/profile").ToString();

        var tasks = Enumerable.Range(0, 160).Select(async _ =>
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
            var accessToken = TestTokenIssuer.MintAccessToken(jkt);
            using var request = CreateSignedRequest(ecdsa, jwkObject, accessToken, HttpMethod.Get, requestUrl);
            var response = await client.SendAsync(request, CancellationToken.None);

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

        Assert.True(successCount <= 102,
            $"Expected at most 102 successful requests (100 permits + queue of 2), but got {successCount}");
        Assert.True(rateLimitedCount > 0, "Expected at least one 429 TooManyRequests response.");
    }

    [Fact]
    public async Task S15_DocumentsList_WithReadScopeAndAcr2_Returns200()
    {
        var requestUrl = new Uri(client.BaseAddress!, "/v1/documents").ToString();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ecdsa));
        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };

        var token = TestTokenIssuer.MintAccessToken(
            ComputeEcThumbprint(jwkObject),
            "acr2",
            "documents:read",
            subject: "documents-user-1");

        using var request = CreateSignedRequest(ecdsa, jwkObject, token, HttpMethod.Get, requestUrl);
        var response = await client.SendAsync(request, CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task S16_StepUpRequired_WithLowerAcr_Returns401()
    {
        var requestUrl = new Uri(client.BaseAddress!, "/v1/test/step-up").ToString();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ecdsa));
        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };

        // Token with ACR2 should fail when ACR3 is required
        var token = TestTokenIssuer.MintAccessToken(
            ComputeEcThumbprint(jwkObject),
            "acr2",
            "test:read",
            subject: "test-user-1");

        using var request = CreateSignedRequest(ecdsa, jwkObject, token, HttpMethod.Get, requestUrl);
        var response = await client.SendAsync(request, CancellationToken.None);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task S17_StepUpRequired_WithAcr3_Returns200()
    {
        var requestUrl = new Uri(client.BaseAddress!, "/v1/test/step-up").ToString();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ecdsa));
        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };

        var token = TestTokenIssuer.MintAccessToken(
            ComputeEcThumbprint(jwkObject),
            "acr3",
            "test:read",
            subject: "test-user-2");

        using var request = CreateSignedRequest(ecdsa, jwkObject, token, HttpMethod.Get, requestUrl);
        var response = await client.SendAsync(request, CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task S17B_DocumentsCreate_WithoutSurgicalAuth_Returns401()
    {
        var requestUrl = new Uri(client.BaseAddress!, "/v1/documents").ToString();
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

        var token = TestTokenIssuer.MintAccessToken(
            jkt,
            "acr3",
            "documents:write",
            subject: "documents-user-3");

        using var request = CreateSignedJsonRequest(
            ecdsa,
            jwkObject,
            token,
            HttpMethod.Post,
            requestUrl,
            new { title = "secrets", content = "content" });
        request.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString());

        var response = await client.SendAsync(request, CancellationToken.None);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("insufficient_user_authentication", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task S18_DocumentsCreate_WithSameIdempotencyKey_Returns204OnRetry()
    {
        var requestUrl = new Uri(client.BaseAddress!, "/v1/documents").ToString();
        const string subject = "documents-user-4";
        var idempotencyKey = Guid.NewGuid().ToString();

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

        var token1 = TestTokenIssuer.MintAccessToken(jkt, "acr3", "documents:write", subject: subject);
        using var request1 = CreateSignedJsonRequest(
            ecdsa,
            jwkObject,
            token1,
            HttpMethod.Post,
            requestUrl,
            new { title = "invoice", content = "v1" });
        request1.Headers.Add("Idempotency-Key", idempotencyKey);

        var response1 = await client.SendAsync(request1, CancellationToken.None);
        Assert.Equal(HttpStatusCode.Created, response1.StatusCode);
        Assert.True(response1.Headers.TryGetValues("DPoP-Nonce", out var nonceValues));
        var nonce = nonceValues!.First();

        var token2 = TestTokenIssuer.MintAccessToken(jkt, "acr3", "documents:write", subject: subject);
        using var request2 = CreateSignedJsonRequest(
            ecdsa,
            jwkObject,
            token2,
            HttpMethod.Post,
            requestUrl,
            new { title = "invoice", content = "v2" },
            nonce);
        request2.Headers.Add("Idempotency-Key", idempotencyKey);

        var response2 = await client.SendAsync(request2, CancellationToken.None);
        Assert.Equal(HttpStatusCode.NoContent, response2.StatusCode);
    }

    [Fact]
    public async Task S19_DocumentsGetById_PreventsCrossSubjectAccess_Returns404()
    {
        var createUrl = new Uri(client.BaseAddress!, "/v1/documents").ToString();
        const string ownerSub = "documents-owner";

        using var ownerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ownerJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ownerKey));
        var ownerJwkObject = new Dictionary<string, string>
        {
            ["crv"] = ownerJwk.Crv!,
            ["kty"] = ownerJwk.Kty!,
            ["x"] = ownerJwk.X!,
            ["y"] = ownerJwk.Y!
        };

        var ownerToken = TestTokenIssuer.MintAccessToken(
            ComputeEcThumbprint(ownerJwkObject),
            "acr3",
            "documents:write",
            subject: ownerSub);

        using var createRequest = CreateSignedJsonRequest(
            ownerKey,
            ownerJwkObject,
            ownerToken,
            HttpMethod.Post,
            createUrl,
            new { title = "contract", content = "internal" });
        createRequest.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString());

        var createResponse = await client.SendAsync(createRequest, CancellationToken.None);
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);

        var createdJson = await createResponse.Content.ReadAsStringAsync(CancellationToken.None);
        using var createdDoc = JsonDocument.Parse(createdJson);
        var documentId = createdDoc.RootElement.GetProperty("id").GetGuid();

        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var attackerJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(attackerKey));
        var attackerJwkObject = new Dictionary<string, string>
        {
            ["crv"] = attackerJwk.Crv!,
            ["kty"] = attackerJwk.Kty!,
            ["x"] = attackerJwk.X!,
            ["y"] = attackerJwk.Y!
        };

        var attackerToken = TestTokenIssuer.MintAccessToken(
            ComputeEcThumbprint(attackerJwkObject),
            "acr2",
            "documents:read",
            subject: "documents-attacker");

        var readUrl = new Uri(client.BaseAddress!, $"/v1/documents/{documentId}").ToString();
        using var readRequest =
            CreateSignedRequest(attackerKey, attackerJwkObject, attackerToken, HttpMethod.Get, readUrl);

        var readResponse = await client.SendAsync(readRequest, CancellationToken.None);
        Assert.Equal(HttpStatusCode.NotFound, readResponse.StatusCode);
    }

    [Fact]
    public async Task S20_DocumentsDelete_RequiresMtlsBinding_Returns403WithoutCertificate()
    {
        var createUrl = new Uri(client.BaseAddress!, "/v1/documents").ToString();
        const string ownerSub = "documents-user-5";

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(key));
        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };
        var jkt = ComputeEcThumbprint(jwkObject);

        var createToken = TestTokenIssuer.MintAccessToken(jkt, "acr3", "documents:write", subject: ownerSub);
        using var createRequest = CreateSignedJsonRequest(
            key,
            jwkObject,
            createToken,
            HttpMethod.Post,
            createUrl,
            new { title = "to-delete", content = "demo" });
        createRequest.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString());

        var createResponse = await client.SendAsync(createRequest, CancellationToken.None);
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        Assert.True(createResponse.Headers.TryGetValues("DPoP-Nonce", out var nonceValues));
        var nonce = nonceValues!.First();
        using var createdDoc =
            JsonDocument.Parse(await createResponse.Content.ReadAsStringAsync(CancellationToken.None));
        var documentId = createdDoc.RootElement.GetProperty("id").GetGuid();

        var deleteToken = TestTokenIssuer.MintAccessToken(jkt, "acr3", "documents:write", subject: ownerSub);
        var deleteUrl = new Uri(client.BaseAddress!, $"/v1/documents/{documentId}").ToString();
        using var deleteRequest = CreateSignedRequest(key, jwkObject, deleteToken, HttpMethod.Delete, deleteUrl, nonce);
        deleteRequest.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString());

        var deleteResponse = await client.SendAsync(deleteRequest, CancellationToken.None);

        Assert.Equal(HttpStatusCode.Forbidden, deleteResponse.StatusCode);
        var problemJson = await deleteResponse.Content.ReadAsStringAsync(CancellationToken.None);
        Assert.Contains("/errors/mtls-binding-failed", problemJson);
    }

    private static HttpRequestMessage CreateSignedRequest(
        ECDsa ecdsa,
        Dictionary<string, string> jwkObject,
        string accessToken,
        HttpMethod method,
        string url,
        string? nonce = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = method.Method,
            ["htu"] = url,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        if (!string.IsNullOrWhiteSpace(nonce))
        {
            claims["nonce"] = nonce;
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
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

    private static HttpRequestMessage CreateSignedJsonRequest(
        ECDsa ecdsa,
        Dictionary<string, string> jwkObject,
        string accessToken,
        HttpMethod method,
        string url,
        object body,
        string? nonce = null)
    {
        var request = CreateSignedRequest(ecdsa, jwkObject, accessToken, method, url, nonce);
        request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        return request;
    }

    private static string CreateDpopProof(ECDsaSecurityKey securityKey, Dictionary<string, string> jwkObject,
        string jti, string url, string? nonce)
    {
        var claims = new Dictionary<string, object>
        {
            ["jti"] = jti,
            ["htm"] = "GET",
            ["htu"] = url,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        if (!string.IsNullOrWhiteSpace(nonce))
        {
            claims["nonce"] = nonce;
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = jwkObject
            }
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
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
