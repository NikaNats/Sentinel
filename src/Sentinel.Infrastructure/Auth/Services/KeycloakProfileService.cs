using System.Net.Http.Json;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Keycloak;

namespace Sentinel.Infrastructure.Auth.Services;

public sealed class KeycloakProfileService(HttpClient httpClient) : IKeycloakProfileService
{
    public async Task<bool> UpdateProfileAsync(string subjectId, string? displayName, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            return false;
        }

        var normalizedDisplayName = string.IsNullOrWhiteSpace(displayName) ? string.Empty : displayName.Trim();
        var parts = normalizedDisplayName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var firstName = parts.Length > 0 ? parts[0] : string.Empty;
        var lastName = parts.Length > 1 ? string.Join(' ', parts.Skip(1)) : string.Empty;

        var payload = new KeycloakAdminUserUpdatePayload
        {
            FirstName = firstName,
            LastName = lastName,
            Attributes = new Dictionary<string, string[]>
            {
                ["display_name"] = [normalizedDisplayName]
            }
        };

        using var response = await httpClient.PutAsJsonAsync(
            $"users/{Uri.EscapeDataString(subjectId)}",
            payload,
            KeycloakJsonContext.Default.KeycloakAdminUserUpdatePayload,
            ct);

        return response.IsSuccessStatusCode;
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

        var payload = new KeycloakAdminPasswordResetPayload
        {
            Type = "password",
            Value = newPassword,
            Temporary = false
        };

        using var response = await httpClient.PutAsJsonAsync(
            $"users/{Uri.EscapeDataString(user.Id!)}/reset-password",
            payload,
            KeycloakJsonContext.Default.KeycloakAdminPasswordResetPayload,
            ct);

        return response.IsSuccessStatusCode;
    }

    private async Task<KeycloakUserResponse?> GetUserByEmailAsync(string email, CancellationToken ct)
    {
        var encodedEmail = Uri.EscapeDataString(email.Trim());
        using var response = await httpClient.GetAsync($"users?email={encodedEmail}&exact=true", ct);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var users = await response.Content.ReadFromJsonAsync(
            KeycloakJsonContext.Default.ListKeycloakUserResponse,
            ct);
        return users?.FirstOrDefault(static u => !string.IsNullOrWhiteSpace(u.Id));
    }
}
