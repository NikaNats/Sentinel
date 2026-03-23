using System.Net.Http.Json;
using Sentinel.Security.Abstractions.Identity;
using Sentinel.Keycloak;

namespace Sentinel.Infrastructure.Auth.Services;

internal sealed class KeycloakProfileService(HttpClient httpClient) : IUserProfileManager
{
    public async Task<bool> UpdateProfileAsync(string subjectId, string? displayName, CancellationToken cancellationToken = default)
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
            cancellationToken);

        return response.IsSuccessStatusCode;
    }
}
