using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.Tests.Integration.Federation;

[Collection("Sentinel Real Keycloak Integration")]
public sealed class TokenExchangeWithRealKeycloakTests(RealKeycloakApiFactory factory)
{
    private readonly HttpClient apiClient = factory.CreateClient();

    [Fact]
    public async Task TokenExchange_WhenDpopProofMissing_Returns400()
    {
        var response = await apiClient.PostAsJsonAsync(
            "/v1/auth/token-exchange",
            new { externalToken = "fake-google-token", providerName = "google", codeVerifier = "pkce-verifier-123" },
            CancellationToken.None);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task TokenExchange_WhenProviderConfiguredButExternalTokenInvalid_Returns401()
    {
        await ConfigureGoogleIdentityProviderAsync();

        var requestUrl = new Uri(apiClient.BaseAddress!, "/v1/auth/token-exchange").ToString();
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl)
        {
            Content = JsonContent.Create(new
                { externalToken = "fake-google-token", providerName = "google", codeVerifier = "pkce-verifier-123" })
        };
        request.Headers.Add("DPoP", CreateDpopProof(requestUrl));

        var response = await apiClient.SendAsync(request, CancellationToken.None);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    private async Task ConfigureGoogleIdentityProviderAsync()
    {
        var adminToken = await GetMasterAdminTokenAsync();
        var authority = factory.Authority.TrimEnd('/');
        var realmName = authority.Split('/', StringSplitOptions.RemoveEmptyEntries).Last();
        var host = authority[..authority.IndexOf("/realms/", StringComparison.OrdinalIgnoreCase)];

        using var adminClient = new HttpClient();
        adminClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        var payload = new
        {
            alias = "google",
            displayName = "Google",
            providerId = "google",
            enabled = true,
            trustEmail = true,
            storeToken = true,
            firstBrokerLoginFlowAlias = "first broker login",
            config = new Dictionary<string, string>
            {
                ["clientId"] = "test-client-id",
                ["clientSecret"] = "test-client-secret",
                ["defaultScope"] = "openid profile email",
                ["useJwksUrl"] = "true",
                ["syncMode"] = "IMPORT"
            }
        };

        using var upsert =
            new HttpRequestMessage(HttpMethod.Post, $"{host}/admin/realms/{realmName}/identity-provider/instances")
            {
                Content = JsonContent.Create(payload)
            };

        var result = await adminClient.SendAsync(upsert, CancellationToken.None);
        if (result.StatusCode == HttpStatusCode.Conflict)
        {
            return;
        }

        result.EnsureSuccessStatusCode();
    }

    private async Task<string> GetMasterAdminTokenAsync()
    {
        var authority = factory.Authority.TrimEnd('/');
        var host = authority[..authority.IndexOf("/realms/", StringComparison.OrdinalIgnoreCase)];
        var tokenEndpoint = $"{host}/realms/master/protocol/openid-connect/token";

        using var client = new HttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("grant_type", "password"),
                new KeyValuePair<string, string>("client_id", "admin-cli"),
                new KeyValuePair<string, string>("username", "admin"),
                new KeyValuePair<string, string>("password", "admin")
            ])
        };

        using var response = await client.SendAsync(request, CancellationToken.None);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadFromJsonAsync<Dictionary<string, object>>(CancellationToken.None);
        return json?["access_token"]?.ToString() ?? throw new InvalidOperationException("Missing access_token");
    }

    private static string CreateDpopProof(string requestUrl)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new ECDsaSecurityKey(ecdsa) { KeyId = Guid.NewGuid().ToString("N") };
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["htm"] = "POST",
                ["htu"] = requestUrl,
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
}
