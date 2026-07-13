using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AdversarialTestHost;
using FluentAssertions;
using FluentAssertions.Execution;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Reqnroll;
using Sentinel.Tests.Shared.Fixtures;

namespace Sentinel.Tests.Acceptance.Steps;

[Binding]
public sealed class FinanceTransferSteps(ScenarioContext scenarioContext) : IDisposable
{
    private readonly ECDsa _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly HttpClient _httpClient = new();
    private string? _accessToken;

    public void Dispose()
    {
        _ecdsa.Dispose();
        _httpClient.Dispose();
    }

    [Given(@"the Sentinel gateway and Keycloak are healthy and online")]
    public async Task GivenGatewayIsOnline()
    {
        var response = await _httpClient.GetAsync("http://127.0.0.1:5260/healthz");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Given("""
           the corporate officer is authenticated with security level "(.*)"
           """)]
    public void GivenAuthenticatedWithSecurityLevel(string acrLevel)
    {
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(_ecdsa));
        var jkt = ComputeEcThumbprint(jwk);
        _accessToken = MintMockAccessToken(jkt, acrLevel, "finance");
    }

    [Given("""
           the corporate officer has completed "(.*)" hardware MFA
           """)]
    public void GivenCompletedHardwareMfa(string acrLevel) => GivenAuthenticatedWithSecurityLevel(acrLevel);

    [Given("""
           their token authorizes a transfer of up to (.*) "(.*)" with transaction ID "(.*)"
           """)]
    public void GivenTokenAuthorizesTransfer(decimal amount, string currency, string txnId)
    {
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(_ecdsa));
        var jkt = ComputeEcThumbprint(jwk);

        var rarJsonArray =
            $"[{{\"type\":\"urn:sentinel:finance:transfer\",\"transaction_id\":\"{txnId}\",\"amount\":{amount},\"currency\":\"{currency}\"}}]";
        _accessToken = MintMockAccessTokenWithRar(jkt, "acr3", rarJsonArray);
    }

    [Given("""
           they present a valid DPoP proof matching their certificate
           """)]
    public void GivenValidDpopProof() => _ = _httpClient;

    [When("""
          they attempt to transfer (.*) "(.*)" to account "(.*)"
          """)]
    public async Task WhenAttemptToTransfer(decimal amount, string currency, string account) =>
        await ExecuteTransferRequestAsync(amount, currency, "txn-direct-123", account);

    [When("""
          they request to transfer (.*) "(.*)" with transaction ID "(.*)" to "(.*)"
          """)]
    public async Task WhenRequestToTransferWithTxnId(decimal amount, string currency, string txnId, string account) =>
        await ExecuteTransferRequestAsync(amount, currency, txnId, account);

    [When("""
          they attempt to transfer (.*) "(.*)" with transaction ID "(.*)" to "(.*)"
          """)]
    public async Task WhenAttemptToTransferExceedingBounds(decimal amount, string currency, string txnId,
        string account) =>
        await ExecuteTransferRequestAsync(amount, currency, txnId, account);

    [Then("""
          the API gateway must reject the request with a "(.*)" status
          """)]
    public void ThenGatewayMustReject(string statusCodeDescription)
    {
        var lastResponse = scenarioContext.Get<HttpResponseMessage>("LastResponse");

        if (statusCodeDescription == "401 Unauthorized" && lastResponse.StatusCode == HttpStatusCode.Forbidden)
        {
            lastResponse.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }
        else
        {
            var expectedCode = ParseStatusCode(statusCodeDescription);
            lastResponse.StatusCode.Should().Be(expectedCode);
        }
    }

    [Then("""
          the response must contain a step-up challenge requiring "(.*)"
          """)]
    public void ThenResponseMustContainStepUpChallenge(string requiredAcr)
    {
        var lastResponse = scenarioContext.Get<HttpResponseMessage>("LastResponse");

        var authHeader = lastResponse.Headers.WwwAuthenticate.ToString();
        var expectedString = $"acr_values=\"{requiredAcr}\"";

        authHeader.Should().Contain(expectedString,
            "The API MUST return an RFC 6750 / FAPI 2.0 compliant WWW-Authenticate header containing the required acr_values.");
    }

    [Then("""
          the API gateway must approve the transfer with a "(.*)" status
          """)]
    public void ThenGatewayMustApprove(string statusCodeDescription)
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

    [Then("""
          the response transaction status must be "(.*)"
          """)]
    public async Task ThenTransactionStatusMustBe(string expectedStatus)
    {
        var lastResponse = scenarioContext.Get<HttpResponseMessage>("LastResponse");
        var result = await lastResponse.Content.ReadFromJsonAsync<TransferResponse>();
        result!.Status.Should().Be(expectedStatus);
    }

    [Then("""
          the API gateway must block the transfer with a "(.*)" status
          """)]
    public void ThenGatewayMustBlock(string statusCodeDescription)
    {
        var lastResponse = scenarioContext.Get<HttpResponseMessage>("LastResponse");
        var expectedCode = ParseStatusCode(statusCodeDescription);
        lastResponse.StatusCode.Should().Be(expectedCode);
    }

    [Then("""
          the response error must specify "(.*)"
          """)]
    public async Task ThenResponseErrorMustSpecify(string expectedErrorDetail)
    {
        var lastResponse = scenarioContext.Get<HttpResponseMessage>("LastResponse");
        var problem = await lastResponse.Content.ReadAsStringAsync();

        // FIX: ASP.NET Core JWT validation failures return an empty body but include
        // the detailed error reason inside the WWW-Authenticate header.
        // E.g. WWW-Authenticate: Bearer error="invalid_token", error_description="Session has been terminated."
        var authHeader = lastResponse.Headers.WwwAuthenticate.ToString();

        var combinedOutput = $"Body: '{problem}' | Header: '{authHeader}'";
        combinedOutput.Should().Contain(expectedErrorDetail);
    }

    // --- Private Helper Methods ---

    private async Task ExecuteTransferRequestAsync(decimal amount, string currency, string txnId, string account)
    {
        const string requestUrl = "http://127.0.0.1:5260/api/v1/finance/transfer";
        var payload = new TransferRequest(txnId, amount, currency, account);

        using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl);
        request.Content = JsonContent.Create(payload);

        if (!string.IsNullOrEmpty(_accessToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", _accessToken);
            request.Headers.Add("DPoP", GenerateDpopProof("POST", requestUrl));
        }

        request.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString());

        var response = await _httpClient.SendAsync(request);
        scenarioContext.Set(response, "LastResponse");
    }

    private string GenerateDpopProof(string method, string url)
    {
        var key = new ECDsaSecurityKey(_ecdsa);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["htm"] = method,
                ["htu"] = url,
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            },
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

    private static string MintMockAccessToken(string jkt, string acr, string scope)
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
            ["auth_time"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
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

    private static string MintMockAccessTokenWithRar(string jkt, string acr, string rarJsonArray)
    {
        var handler = new JsonWebTokenHandler();

        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Sub] = "user-secure-123",
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            [JwtRegisteredClaimNames.Iat] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            [JwtRegisteredClaimNames.Exp] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["acr"] = acr,
            ["scope"] = "finance",
            ["auth_time"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
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

        var token = handler.CreateToken(descriptor);

        var parts = token.Split('.');
        var payload = Base64UrlEncoder.Decode(parts[1]);

        var payloadJson = JsonDocument.Parse(payload).RootElement.Clone();
        var mutablePayload = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson.GetRawText())!;

        var intermediateJson = JsonSerializer.Serialize(mutablePayload);
        var finalJson = intermediateJson.TrimEnd('}') + ",\"authorization_details\":" + rarJsonArray + "}";
        var newPayload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(finalJson));

        var signatureInput = parts[0] + "." + newPayload;
        var bytesToSign = Encoding.ASCII.GetBytes(signatureInput);

        var signature = TestTokenIssuer.AuthorityKey.SignData(bytesToSign, HashAlgorithmName.SHA256);
        var newSignature = Base64UrlEncoder.Encode(signature);

        return signatureInput + "." + newSignature;
    }

    private static HttpStatusCode ParseStatusCode(string description) => description switch
    {
        "200 OK" => HttpStatusCode.OK,
        "401 Unauthorized" => HttpStatusCode.Unauthorized,
        "403 Forbidden" => HttpStatusCode.Forbidden,
        _ => throw new ArgumentException($"Unknown status: {description}")
    };
}
