using System.Net;
using System.Net.Http.Json;
using Sentinel.Security.Abstractions.Identity;

namespace Sentinel.Keycloak.Services;

internal sealed class KeycloakFederationService(HttpClient httpClient) : IIdentityFederationProvider
{
    public async Task ConfigureGoogleProviderAsync(
        string clientId,
        string clientSecret,
        string firstBrokerLoginFlowAlias,
        bool trustEmail = true,
        bool storeToken = true,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
        {
            return;
        }

        var payload = new KeycloakIdentityProviderPayload
        {
            Alias = "google",
            DisplayName = "Google",
            ProviderId = "google",
            Enabled = true,
            TrustEmail = trustEmail,
            StoreToken = storeToken,
            FirstBrokerLoginFlowAlias = firstBrokerLoginFlowAlias,
            Config = new Dictionary<string, string>
            {
                ["clientId"] = clientId,
                ["clientSecret"] = clientSecret,
                ["defaultScope"] = "openid profile email",
                ["useJwksUrl"] = "true",
                ["syncMode"] = "IMPORT"
            }
        };

        await UpsertIdentityProviderAsync(payload, cancellationToken);
    }

    public async Task ConfigureGitHubProviderAsync(
        string clientId,
        string clientSecret,
        string firstBrokerLoginFlowAlias,
        bool trustEmail = true,
        bool storeToken = true,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
        {
            return;
        }

        var payload = new KeycloakIdentityProviderPayload
        {
            Alias = "github",
            DisplayName = "GitHub",
            ProviderId = "github",
            Enabled = true,
            TrustEmail = trustEmail,
            StoreToken = storeToken,
            FirstBrokerLoginFlowAlias = firstBrokerLoginFlowAlias,
            Config = new Dictionary<string, string>
            {
                ["clientId"] = clientId,
                ["clientSecret"] = clientSecret,
                ["defaultScope"] = "read:user user:email",
                ["syncMode"] = "IMPORT"
            }
        };

        await UpsertIdentityProviderAsync(payload, cancellationToken);
    }

    private async Task UpsertIdentityProviderAsync(KeycloakIdentityProviderPayload payload, CancellationToken ct)
    {
        var instancePath = $"identity-provider/instances/{Uri.EscapeDataString(payload.Alias)}";
        using var getResponse = await httpClient.GetAsync(instancePath, ct);

        if (getResponse.StatusCode == HttpStatusCode.NotFound)
        {
            using var createResponse = await httpClient.PostAsJsonAsync(
                "identity-provider/instances",
                payload,
                KeycloakJsonContext.Default.KeycloakIdentityProviderPayload,
                ct);
            createResponse.EnsureSuccessStatusCode();
            return;
        }

        getResponse.EnsureSuccessStatusCode();

        using var updateResponse = await httpClient.PutAsJsonAsync(
            instancePath,
            payload,
            KeycloakJsonContext.Default.KeycloakIdentityProviderPayload,
            ct);
        updateResponse.EnsureSuccessStatusCode();
    }
}
