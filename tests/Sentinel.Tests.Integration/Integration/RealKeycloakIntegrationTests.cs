using System.Net;
using System.Net.Http.Headers;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Sentinel.Tests.Integration;

[Collection("Sentinel Real Keycloak Integration")]
public sealed class RealKeycloakIntegrationTests(RealKeycloakApiFactory factory)
{
    private readonly HttpClient apiClient = factory.CreateClient();

    [Fact]
    public async Task LiveKeycloakToken_WithDpopProof_IssuesBoundAccessToken()
    {
        using var keycloakHttp = factory.CreateKeycloakHttpClient();
        var tokenClient = new KeycloakDpopTokenClient(factory.TokenEndpoint);

        var token = await tokenClient.RequestClientCredentialsGrantAsync(
            keycloakHttp,
            RealKeycloakApiFactory.ClientId,
            RealKeycloakApiFactory.ClientSecret);

        Assert.False(string.IsNullOrWhiteSpace(token.AccessToken));

        var jwt = new JsonWebToken(token.AccessToken);
        Assert.Contains($"/realms/{RealKeycloakApiFactory.RealmName}", jwt.Issuer);
        Assert.True(jwt.TryGetPayloadValue<string>("azp", out var authorizedParty));
        Assert.Equal(RealKeycloakApiFactory.ClientId, authorizedParty);
    }

    [Fact]
    public async Task LiveKeycloakToken_WithoutValidBinding_IsRejectedFailClosed()
    {
        using var keycloakHttp = factory.CreateKeycloakHttpClient();
        var tokenClient = new KeycloakDpopTokenClient(factory.TokenEndpoint);

        var token = await tokenClient.RequestClientCredentialsGrantAsync(
            keycloakHttp,
            RealKeycloakApiFactory.ClientId,
            RealKeycloakApiFactory.ClientSecret);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/profile");
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", token.AccessToken);
        using var response = await apiClient.SendAsync(request, CancellationToken.None);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("missing_dpop_proof", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task LiveKeycloakToken_WithDifferentDpopKey_IsRejected()
    {
        using var keycloakHttp = factory.CreateKeycloakHttpClient();
        var issuerKeyClient = new KeycloakDpopTokenClient(factory.TokenEndpoint);
        var attackerKeyClient = new KeycloakDpopTokenClient(factory.TokenEndpoint);

        var token = await issuerKeyClient.RequestClientCredentialsGrantAsync(
            keycloakHttp,
            RealKeycloakApiFactory.ClientId,
            RealKeycloakApiFactory.ClientSecret);

        using var request = attackerKeyClient.CreateApiRequest(HttpMethod.Get,
            new Uri(apiClient.BaseAddress!, "/v1/profile"), token.AccessToken);

        using var response = await apiClient.SendAsync(request, CancellationToken.None);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("invalid_dpop_proof", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task LiveKeycloakBearerDowngrade_IsRejected()
    {
        using var keycloakHttp = factory.CreateKeycloakHttpClient();
        var tokenClient = new KeycloakDpopTokenClient(factory.TokenEndpoint);

        var token = await tokenClient.RequestClientCredentialsGrantAsync(
            keycloakHttp,
            RealKeycloakApiFactory.ClientId,
            RealKeycloakApiFactory.ClientSecret);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/profile");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);

        using var response = await apiClient.SendAsync(request, CancellationToken.None);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("invalid_dpop_proof", response.Headers.WwwAuthenticate.ToString());
    }
}
