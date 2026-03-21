using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sentinel.Tests.Integration.Fixtures;

public sealed class KeycloakDpopTokenClient(string tokenEndpoint)
{
    private readonly ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public async Task<TokenResponse> RequestClientCredentialsGrantAsync(HttpClient httpClient, string clientId, string clientSecret)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret)
            ])
        };

        request.Headers.Add("DPoP", CreateProof(HttpMethod.Post.Method, tokenEndpoint));

        using var response = await httpClient.SendAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            var failureBody = await response.Content.ReadAsStringAsync();
            throw new HttpRequestException($"Keycloak client credentials grant failed with {(int)response.StatusCode}: {failureBody}");
        }

        var json = await response.Content.ReadAsStringAsync();
        return ParseTokenResponse(json);
    }

    public async Task<TokenResponse> RequestRefreshGrantAsync(HttpClient httpClient, string refreshToken, string clientId)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("refresh_token", refreshToken)
            ])
        };

        request.Headers.Add("DPoP", CreateProof(HttpMethod.Post.Method, tokenEndpoint));

        using var response = await httpClient.SendAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            var failureBody = await response.Content.ReadAsStringAsync();
            throw new HttpRequestException($"Keycloak refresh grant failed with {(int)response.StatusCode}: {failureBody}");
        }

        var json = await response.Content.ReadAsStringAsync();
        return ParseTokenResponse(json);
    }

    public HttpRequestMessage CreateApiRequest(HttpMethod method, Uri url, string accessToken)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        request.Headers.Add("DPoP", CreateProof(method.Method, url.ToString()));
        return request;
    }

    public string CreateProofForTokenEndpoint(HttpMethod method)
    {
        return CreateProof(method.Method, tokenEndpoint);
    }

    private string CreateProof(string method, string url)
    {
        var key = new ECDsaSecurityKey(signingKey) { KeyId = Guid.NewGuid().ToString("N") };
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);

        var jwkObject = new Dictionary<string, string>
        {
            ["kty"] = jwk.Kty!,
            ["crv"] = jwk.Crv!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };

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
                ["jwk"] = jwkObject
            }
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static TokenResponse ParseTokenResponse(string json)
    {
        using var doc = JsonDocument.Parse(json);

        var accessToken = doc.RootElement.GetProperty("access_token").GetString();
        var refreshToken = doc.RootElement.TryGetProperty("refresh_token", out var refresh)
            ? refresh.GetString()
            : null;

        if (string.IsNullOrWhiteSpace(accessToken))
        {
            throw new InvalidOperationException("Token response did not include an access token.");
        }

        return new TokenResponse(accessToken, refreshToken);
    }
}

public sealed record TokenResponse(string AccessToken, string? RefreshToken);
