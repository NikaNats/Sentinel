using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Domain.Users;

namespace Sentinel.Infrastructure.Auth;

public sealed class KeycloakAdminService(
    IHttpClientFactory httpClientFactory,
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

        var client = httpClientFactory.CreateClient("keycloak-admin");
        using var response = await client.SendAsync(request, ct);

        if (!response.IsSuccessStatusCode)
        {
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

        var client = httpClientFactory.CreateClient("keycloak-admin");
        using var response = await client.SendAsync(request, ct);

        return response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NoContent;
    }

    public async Task<bool> DeleteUserAsync(string keycloakUserId, CancellationToken ct)
    {
        var adminRealmEndpoint = ResolveAdminRealmEndpoint();
        var token = await RequireAdminTokenAsync(ct);

        using var request = new HttpRequestMessage(HttpMethod.Delete, new Uri(adminRealmEndpoint, $"users/{Uri.EscapeDataString(keycloakUserId)}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var client = httpClientFactory.CreateClient("keycloak-admin");
        using var response = await client.SendAsync(request, ct);

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

        var client = httpClientFactory.CreateClient("keycloak-admin");
        using var response = await client.SendAsync(request, ct);
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

        var client = httpClientFactory.CreateClient("keycloak-admin");
        using var response = await client.SendAsync(request, ct);
        return response.IsSuccessStatusCode;
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

    private sealed class KeycloakUserResponse
    {
        public string? Id { get; set; }
        public string? Email { get; set; }
        public string? Username { get; set; }
    }
}
