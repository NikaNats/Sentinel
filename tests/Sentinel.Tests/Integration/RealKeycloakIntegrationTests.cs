using Sentinel.Tests.Integration.Fixtures;
using System.Net;
namespace Sentinel.Tests.Integration;

[Collection("Sentinel Real Keycloak Integration")]
public sealed class RealKeycloakIntegrationTests(RealKeycloakApiFactory factory)
{
    private readonly HttpClient apiClient = factory.CreateClient();

    [Fact]
    public async Task LiveKeycloakToken_WithoutValidBinding_IsRejectedFailClosed()
    {
        using var keycloakHttp = new HttpClient();
        var tokenClient = new KeycloakDpopTokenClient(factory.TokenEndpoint);

        var token = await tokenClient.RequestClientCredentialsGrantAsync(
            keycloakHttp,
            RealKeycloakApiFactory.ClientId,
            RealKeycloakApiFactory.ClientSecret);

        using var request = tokenClient.CreateApiRequest(HttpMethod.Get, new Uri(apiClient.BaseAddress!, "/v1/profile"), token.AccessToken);
        using var response = await apiClient.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("invalid_dpop_proof", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task LiveKeycloakToken_WithDifferentDpopKey_IsRejected()
    {
        using var keycloakHttp = new HttpClient();
        var issuerKeyClient = new KeycloakDpopTokenClient(factory.TokenEndpoint);
        var attackerKeyClient = new KeycloakDpopTokenClient(factory.TokenEndpoint);

        var token = await issuerKeyClient.RequestClientCredentialsGrantAsync(
            keycloakHttp,
            RealKeycloakApiFactory.ClientId,
            RealKeycloakApiFactory.ClientSecret);

        using var request = attackerKeyClient.CreateApiRequest(HttpMethod.Get, new Uri(apiClient.BaseAddress!, "/v1/profile"), token.AccessToken);

        using var response = await apiClient.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("invalid_dpop_proof", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task LiveKeycloakBearerDowngrade_IsRejected()
    {
        using var keycloakHttp = new HttpClient();
        var tokenClient = new KeycloakDpopTokenClient(factory.TokenEndpoint);

        var token = await tokenClient.RequestClientCredentialsGrantAsync(
            keycloakHttp,
            RealKeycloakApiFactory.ClientId,
            RealKeycloakApiFactory.ClientSecret);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/profile");
        request.Headers.Authorization = new("Bearer", token.AccessToken);

        using var response = await apiClient.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("invalid_dpop_proof", response.Headers.WwwAuthenticate.ToString());
    }
}
