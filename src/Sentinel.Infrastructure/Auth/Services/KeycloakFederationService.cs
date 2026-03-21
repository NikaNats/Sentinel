using System.Net;
using System.Net.Http.Json;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;

namespace Sentinel.Infrastructure.Auth.Services;

public sealed class KeycloakFederationService(HttpClient httpClient) : IKeycloakFederationService
{
    public async Task ConfigureGoogleProviderAsync(GoogleFederationOptions options, string firstBrokerLoginFlowAlias,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(options.ClientId) || string.IsNullOrWhiteSpace(options.ClientSecret))
        {
            return;
        }

        var payload = new KeycloakIdentityProviderPayload
        {
            Alias = "google",
            DisplayName = "Google",
            ProviderId = "google",
            Enabled = true,
            TrustEmail = options.TrustEmail,
            StoreToken = options.StoreToken,
            FirstBrokerLoginFlowAlias = firstBrokerLoginFlowAlias,
            Config = new Dictionary<string, string>
            {
                ["clientId"] = options.ClientId,
                ["clientSecret"] = options.ClientSecret,
                ["defaultScope"] = "openid profile email",
                ["useJwksUrl"] = "true",
                ["syncMode"] = MapSyncMode(options.SyncMode)
            }
        };

        await UpsertIdentityProviderAsync(payload, ct);
    }

    public async Task ConfigureGitHubProviderAsync(GitHubFederationOptions options, string firstBrokerLoginFlowAlias,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(options.ClientId) || string.IsNullOrWhiteSpace(options.ClientSecret))
        {
            return;
        }

        var payload = new KeycloakIdentityProviderPayload
        {
            Alias = "github",
            DisplayName = "GitHub",
            ProviderId = "github",
            Enabled = true,
            TrustEmail = options.TrustEmail,
            StoreToken = options.StoreToken,
            FirstBrokerLoginFlowAlias = firstBrokerLoginFlowAlias,
            Config = new Dictionary<string, string>
            {
                ["clientId"] = options.ClientId,
                ["clientSecret"] = options.ClientSecret,
                ["defaultScope"] = "read:user user:email",
                ["syncMode"] = MapSyncMode(options.SyncMode)
            }
        };

        await UpsertIdentityProviderAsync(payload, ct);
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

    private static string MapSyncMode(FederationSyncMode syncMode)
    {
        return syncMode switch
        {
            FederationSyncMode.Import => "IMPORT",
            FederationSyncMode.Force => "FORCE",
            _ => "LEGACY"
        };
    }
}
