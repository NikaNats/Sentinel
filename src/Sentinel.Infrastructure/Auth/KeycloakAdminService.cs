using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Domain.Users;

namespace Sentinel.Infrastructure.Auth;

public sealed class KeycloakAdminService(
    HttpClient httpClient,
    KeycloakAdminTokenProvider tokenProvider,
    IConfiguration configuration,
    ILogger<KeycloakAdminService> logger) : IKeycloakAdminService
{
    public async Task<string> CreateUserAsync(UserRegistration registration, string password, CancellationToken ct)
    {
        var adminRealmEndpoint = ResolveAdminRealmEndpoint();
        var token = await RequireAdminTokenAsync(ct);

        var payload = new
        {
            email = registration.Email,
            username = registration.Username,
            enabled = true,
            emailVerified = false,
            credentials = new[]
            {
                new { type = "password", value = password, temporary = false }
            },
            attributes = new Dictionary<string, string[]>
            {
                ["consent_date"] = [registration.Consent.AcceptedAtUtc.ToString("O")],
                ["policy_version"] = [registration.Consent.PrivacyPolicyVersion],
                ["consent_ip_hash"] = [registration.Consent.IpAddress]
            }
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(adminRealmEndpoint, "users"))
        {
            Content = JsonContent.Create(payload)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await httpClient.SendAsync(request, ct);

        if (!response.IsSuccessStatusCode)
        {
            if (response.StatusCode == HttpStatusCode.Conflict)
            {
                throw new UserAlreadyExistsException();
            }

            var error = await response.Content.ReadAsStringAsync(ct);
            logger.LogWarning("Failed to create Keycloak user. Status: {Status}. Body: {Body}", (int)response.StatusCode, error);
            throw new InvalidOperationException("Unable to create user in identity provider.");
        }

        var userId = TryExtractUserId(response.Headers.Location);
        if (string.IsNullOrWhiteSpace(userId))
        {
            throw new InvalidOperationException("Identity provider did not return a user identifier.");
        }

        return userId;
    }

    public async Task<bool> SetEmailVerifiedAsync(string keycloakUserId, bool verified, CancellationToken ct)
    {
        var adminRealmEndpoint = ResolveAdminRealmEndpoint();
        var token = await RequireAdminTokenAsync(ct);

        using var request = new HttpRequestMessage(HttpMethod.Put, new Uri(adminRealmEndpoint, $"users/{Uri.EscapeDataString(keycloakUserId)}"))
        {
            Content = JsonContent.Create(new { emailVerified = verified })
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await httpClient.SendAsync(request, ct);

        return response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NoContent;
    }

    public async Task<bool> DeleteUserAsync(string keycloakUserId, CancellationToken ct)
    {
        var adminRealmEndpoint = ResolveAdminRealmEndpoint();
        var token = await RequireAdminTokenAsync(ct);

        using var request = new HttpRequestMessage(HttpMethod.Delete, new Uri(adminRealmEndpoint, $"users/{Uri.EscapeDataString(keycloakUserId)}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await httpClient.SendAsync(request, ct);

        return response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NoContent;
    }

    public async Task<KeycloakUserSummary?> GetUserByEmailAsync(string email, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return null;
        }

        var adminRealmEndpoint = ResolveAdminRealmEndpoint();
        var token = await RequireAdminTokenAsync(ct);

        var encodedEmail = Uri.EscapeDataString(email.Trim());
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(adminRealmEndpoint, $"users?email={encodedEmail}&exact=true"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await httpClient.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var users = await response.Content.ReadFromJsonAsync<List<KeycloakUserResponse>>(cancellationToken: ct);
        var user = users?.FirstOrDefault(static u => !string.IsNullOrWhiteSpace(u.Id));
        if (user is null)
        {
            return null;
        }

        return new KeycloakUserSummary(user.Id!, user.Email ?? email.Trim(), user.Username ?? user.Email ?? string.Empty);
    }

    public async Task<bool> UpdateProfileAsync(string subjectId, string? displayName, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            return false;
        }

        var adminRealmEndpoint = ResolveAdminRealmEndpoint();
        var token = await RequireAdminTokenAsync(ct);

        var normalizedDisplayName = string.IsNullOrWhiteSpace(displayName) ? string.Empty : displayName.Trim();
        var parts = normalizedDisplayName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var firstName = parts.Length > 0 ? parts[0] : string.Empty;
        var lastName = parts.Length > 1 ? string.Join(' ', parts.Skip(1)) : string.Empty;

        using var request = new HttpRequestMessage(HttpMethod.Put, new Uri(adminRealmEndpoint, $"users/{Uri.EscapeDataString(subjectId)}"))
        {
            Content = JsonContent.Create(new
            {
                firstName,
                lastName,
                attributes = new Dictionary<string, string[]>
                {
                    ["display_name"] = [normalizedDisplayName]
                }
            })
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await httpClient.SendAsync(request, ct);
        return response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NoContent;
    }

    public async Task<bool> UpdatePasswordAsync(string email, string newPassword, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(newPassword))
        {
            return false;
        }

        var user = await GetUserByEmailAsync(email, ct);
        if (user is null)
        {
            return false;
        }

        var adminRealmEndpoint = ResolveAdminRealmEndpoint();
        var token = await RequireAdminTokenAsync(ct);

        using var request = new HttpRequestMessage(HttpMethod.Put, new Uri(adminRealmEndpoint, $"users/{Uri.EscapeDataString(user.Id)}/reset-password"))
        {
            Content = JsonContent.Create(new
            {
                type = "password",
                value = newPassword,
                temporary = false
            })
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await httpClient.SendAsync(request, ct);
        return response.IsSuccessStatusCode;
    }

    public async Task<bool> VerifyUserPasswordAsync(string usernameOrEmail, string currentPassword, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(usernameOrEmail) || string.IsNullOrWhiteSpace(currentPassword))
        {
            return false;
        }

        var authority = configuration["Keycloak:Authority"]?.TrimEnd('/');
        var clientId = configuration["Keycloak:Audience"];
        if (string.IsNullOrWhiteSpace(authority) || string.IsNullOrWhiteSpace(clientId))
        {
            return false;
        }

        var endpoint = $"{authority}/protocol/openid-connect/token";
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("grant_type", "password"),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("username", usernameOrEmail),
                new KeyValuePair<string, string>("password", currentPassword)
            ])
        };

        using var response = await httpClient.SendAsync(request, ct);
        return response.IsSuccessStatusCode;
    }

    public async Task ConfigureGoogleProviderAsync(GoogleFederationOptions options, string firstBrokerLoginFlowAlias, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(options.ClientId) || string.IsNullOrWhiteSpace(options.ClientSecret))
        {
            return;
        }

        var payload = new IdentityProviderPayload
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

    public async Task ConfigureGitHubProviderAsync(GitHubFederationOptions options, string firstBrokerLoginFlowAlias, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(options.ClientId) || string.IsNullOrWhiteSpace(options.ClientSecret))
        {
            return;
        }

        var payload = new IdentityProviderPayload
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

    private async Task<string> RequireAdminTokenAsync(CancellationToken ct)
    {
        var token = await tokenProvider.GetAccessTokenAsync(ct);
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new InvalidOperationException("Unable to acquire Keycloak admin access token.");
        }

        return token;
    }

    private Uri ResolveAdminRealmEndpoint()
    {
        var authority = configuration["Keycloak:Authority"]?.TrimEnd('/');
        if (string.IsNullOrWhiteSpace(authority)
            || !KeycloakAuthorityEndpoints.TryBuild(authority, out _, out var adminRealmEndpoint))
        {
            throw new InvalidOperationException("Keycloak authority is missing or invalid.");
        }

        return adminRealmEndpoint;
    }

    private static string? TryExtractUserId(Uri? locationHeader)
    {
        if (locationHeader is null)
        {
            return null;
        }

        var segments = locationHeader.Segments;
        if (segments.Length == 0)
        {
            return null;
        }

        return segments[^1].Trim('/');
    }

    private async Task UpsertIdentityProviderAsync(IdentityProviderPayload payload, CancellationToken ct)
    {
        var adminRealmEndpoint = ResolveAdminRealmEndpoint();
        var token = await RequireAdminTokenAsync(ct);
        var instanceEndpoint = new Uri(adminRealmEndpoint, $"identity-provider/instances/{Uri.EscapeDataString(payload.Alias)}");
        using var getRequest = new HttpRequestMessage(HttpMethod.Get, instanceEndpoint);
        getRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var getResponse = await httpClient.SendAsync(getRequest, ct);
        var method = getResponse.StatusCode == HttpStatusCode.NotFound ? HttpMethod.Post : HttpMethod.Put;
        var endpoint = method == HttpMethod.Post
            ? new Uri(adminRealmEndpoint, "identity-provider/instances")
            : instanceEndpoint;

        using var writeRequest = new HttpRequestMessage(method, endpoint)
        {
            Content = JsonContent.Create(payload)
        };
        writeRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var writeResponse = await httpClient.SendAsync(writeRequest, ct);
        writeResponse.EnsureSuccessStatusCode();
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

    private sealed class KeycloakUserResponse
    {
        public string? Id { get; set; }
        public string? Email { get; set; }
        public string? Username { get; set; }
    }

    private sealed class IdentityProviderPayload
    {
        [JsonPropertyName("alias")]
        public string Alias { get; set; } = string.Empty;

        [JsonPropertyName("displayName")]
        public string DisplayName { get; set; } = string.Empty;

        [JsonPropertyName("providerId")]
        public string ProviderId { get; set; } = string.Empty;

        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; }

        [JsonPropertyName("trustEmail")]
        public bool TrustEmail { get; set; }

        [JsonPropertyName("storeToken")]
        public bool StoreToken { get; set; }

        [JsonPropertyName("firstBrokerLoginFlowAlias")]
        public string FirstBrokerLoginFlowAlias { get; set; } = "first broker login";

        [JsonPropertyName("config")]
        public Dictionary<string, string> Config { get; set; } = [];
    }
}
