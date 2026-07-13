using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using FluentAssertions.Execution;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Reqnroll;
using Sentinel.Tests.Shared.Fixtures;

namespace Sentinel.Tests.Acceptance.Steps;

[Binding]
public sealed class SessionRevocationSteps(ScenarioContext scenarioContext) : IDisposable
{
    private readonly ECDsa _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly HttpClient _httpClient = new();
    private string? _accessToken;

    public void Dispose()
    {
        _ecdsa.Dispose();
        _httpClient.Dispose();
    }

    [Given("""
           a corporate officer is authenticated with session ID "(.*)"
           """)]
    public void GivenAuthenticatedWithSession(string sessionId)
    {
        // FIX: Append a GUID to ensure the session ID is unique for this specific test execution.
        // This prevents state pollution in Redis across multiple test runs.
        var uniqueSessionId = $"{sessionId}-{Guid.NewGuid():N}";
        scenarioContext.Set(uniqueSessionId, "UniqueSessionId");

        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(_ecdsa));
        var jkt = ComputeEcThumbprint(jwk);

        _accessToken = MintMockAccessToken(jkt, "acr3", "profile", uniqueSessionId);
    }

    [When(@"they attempt to access their secure profile")]
    public async Task WhenAttemptToAccessProfile() => await ExecuteProfileRequestAsync();

    [Then(@"the API gateway must allow the request with a ""(.*)"" status")]
    public void ThenGatewayMustAllow(string statusCodeDescription)
    {
        var lastResponse = scenarioContext.Get<HttpResponseMessage>("LastResponse");
        var expectedCode = ParseStatusCode(statusCodeDescription);

        if (lastResponse.StatusCode != expectedCode)
        {
            var body = lastResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            var authHeader = lastResponse.Headers.WwwAuthenticate.ToString();
            throw new AssertionFailedException(
                $"Expected status {expectedCode}, but got {lastResponse.StatusCode}.\n" +
                $"Response Body: {body}\n" +
                $"WWW-Authenticate: {authHeader}");
        }
    }

    [When("""
          the identity provider sends a backchannel "session-revoked" SSF event for session ID "(.*)"
          """)]
    public async Task WhenIdpSendsSessionRevokedEvent(string sessionId)
    {
        const string ssfUrl = "http://127.0.0.1:5260/v1/ssf/events";

        // FIX: Retrieve the unique session ID we generated in the Given step
        var uniqueSessionId = scenarioContext.Get<string>("UniqueSessionId");
        var setToken = CreateSignedSsfSetToken(uniqueSessionId);

        using var request = new HttpRequestMessage(HttpMethod.Post, ssfUrl);
        request.Content = JsonContent.Create(new { set = setToken });

        var response = await _httpClient.SendAsync(request);
        scenarioContext.Set(response, "LastResponse");
    }

    [Then("""
          the SSF receiver must accept the event with a "(.*)" status
          """)]
    public void ThenSsfReceiverMustAccept(string statusCodeDescription)
    {
        var lastResponse = scenarioContext.Get<HttpResponseMessage>("LastResponse");
        var expectedCode = ParseStatusCode(statusCodeDescription);
        lastResponse.StatusCode.Should().Be(expectedCode);
    }

    [When(@"they attempt to access their secure profile again with the same session")]
    public async Task WhenAttemptToAccessProfileAgain() => await ExecuteProfileRequestAsync();

    // --- Private Helper Methods ---

    private async Task ExecuteProfileRequestAsync()
    {
        const string requestUrl = "http://127.0.0.1:5260/v1/security-context";

        using var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
        if (!string.IsNullOrEmpty(_accessToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", _accessToken);

            scenarioContext.TryGetValue<string>("ServerNonce", out var cachedNonce);
            request.Headers.Add("DPoP", GenerateDpopProof("GET", requestUrl, cachedNonce));
        }

        var response = await _httpClient.SendAsync(request);

        if (response.Headers.TryGetValues("DPoP-Nonce", out var nonceValues))
        {
            scenarioContext.Set(nonceValues.First(), "ServerNonce");
        }

        scenarioContext.Set(response, "LastResponse");
    }

    private string GenerateDpopProof(string method, string url, string? nonce = null)
    {
        var key = new ECDsaSecurityKey(_ecdsa);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);

        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = method,
            ["htu"] = url,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        if (!string.IsNullOrEmpty(nonce))
        {
            claims["nonce"] = nonce;
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = new Dictionary<string, string>
                {
                    ["kty"] = jwk.Kty!,
                    ["crv"] = jwk.Crv!,
                    ["x"] = jwk.X!,
                    ["y"] = jwk.Y!
                }
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
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static string MintMockAccessToken(string jkt, string acr, string scope, string sessionId)
    {
        var handler = new JsonWebTokenHandler();
        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Sub] = "user-secure-123",
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            [JwtRegisteredClaimNames.Iat] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            [JwtRegisteredClaimNames.Exp] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["acr"] = acr,
            ["scope"] = scope,
            ["sid"] = sessionId, // The unique session ID is injected here
            ["cnf"] = new Dictionary<string, string> { ["jkt"] = jkt }
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "https://localhost:8443/realms/sentinel",
            Audience = "sentinel-api",
            Claims = claims,
            SigningCredentials = new SigningCredentials(
                TestTokenIssuer.AuthoritySecurityKey,
                SecurityAlgorithms.EcdsaSha256)
        };

        return handler.CreateToken(descriptor);
    }

    private static string CreateSignedSsfSetToken(string sid)
    {
        var handler = new JsonWebTokenHandler();

        // The unique session ID is interpolated securely into the CAEP payload
        var eventPayload = JsonDocument.Parse($$"""
                                                {
                                                    "sid": "{{sid}}",
                                                    "sub": "user-secure-123"
                                                }
                                                """).RootElement;

        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Sub] = "user-secure-123",
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            [JwtRegisteredClaimNames.Iat] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            [JwtRegisteredClaimNames.Exp] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["events"] = new Dictionary<string, object>
            {
                ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"] = eventPayload
            }
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "https://localhost:8443/realms/sentinel",
            Audience = "sentinel-api",
            Claims = claims,
            SigningCredentials = new SigningCredentials(
                TestTokenIssuer.AuthoritySecurityKey,
                SecurityAlgorithms.EcdsaSha256)
        };

        return handler.CreateToken(descriptor);
    }

    private static HttpStatusCode ParseStatusCode(string description) => description switch
    {
        "200 OK" => HttpStatusCode.OK,
        "202 Accepted" => HttpStatusCode.Accepted,
        "401 Unauthorized" => HttpStatusCode.Unauthorized,
        "403 Forbidden" => HttpStatusCode.Forbidden,
        _ => throw new ArgumentException($"Unknown status: {description}")
    };
}
