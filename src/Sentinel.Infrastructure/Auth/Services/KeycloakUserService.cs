using System.Net;
using System.Net.Http.Json;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Domain.Users;
using Sentinel.Security.Abstractions.Identity;

namespace Sentinel.Infrastructure.Auth.Services;

public sealed class KeycloakUserService(HttpClient httpClient, ILogger<KeycloakUserService> logger)
    : IKeycloakUserService, IIdentityRegistry
{
    public Task<string> CreateUserAsync(
        IdentityRegistration registration,
        string password,
        CancellationToken cancellationToken = default)
    {
        var legacyRegistration = new UserRegistration
        {
            Email = registration.Email,
            Username = registration.Username,
            Consent = new ConsentInfo(
                registration.AcceptedTerms,
                registration.PolicyVersion,
                registration.AcceptedAtUtc,
                registration.SourceIp)
        };

        return CreateUserAsync(legacyRegistration, password, cancellationToken);
    }

    public async Task<string> CreateUserAsync(UserRegistration registration, string password, CancellationToken ct)
    {
        var payload = new KeycloakAdminCreateUserPayload
        {
            Email = registration.Email,
            Username = registration.Username,
            Enabled = true,
            EmailVerified = false,
            Credentials =
            [
                new KeycloakAdminCredentialPayload
                {
                    Type = "password",
                    Value = password,
                    Temporary = false
                }
            ],
            Attributes = new Dictionary<string, string[]>
            {
                ["consent_date"] = [registration.Consent.AcceptedAtUtc.ToString("O")],
                ["policy_version"] = [registration.Consent.PrivacyPolicyVersion],
                ["consent_ip_hash"] = [registration.Consent.IpAddress]
            }
        };

        using var response = await httpClient.PostAsJsonAsync(
            "users",
            payload,
            KeycloakJsonContext.Default.KeycloakAdminCreateUserPayload,
            ct);

        if (!response.IsSuccessStatusCode)
        {
            if (response.StatusCode == HttpStatusCode.Conflict)
            {
                throw new UserAlreadyExistsException();
            }

            var error = await response.Content.ReadAsStringAsync(ct);
            logger.LogWarning("Failed to create Keycloak user. Status: {Status}. Body: {Body}",
                (int)response.StatusCode, error);
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
        var payload = new KeycloakAdminUserUpdatePayload { EmailVerified = verified };

        using var response = await httpClient.PutAsJsonAsync(
            $"users/{Uri.EscapeDataString(keycloakUserId)}",
            payload,
            KeycloakJsonContext.Default.KeycloakAdminUserUpdatePayload,
            ct);

        return response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NoContent;
    }

    public async Task<bool> DeleteUserAsync(string keycloakUserId, CancellationToken ct)
    {
        using var response = await httpClient.DeleteAsync($"users/{Uri.EscapeDataString(keycloakUserId)}", ct);
        return response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NoContent;
    }

    public async Task<KeycloakUserSummary?> GetUserByEmailAsync(string email, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return null;
        }

        var encodedEmail = Uri.EscapeDataString(email.Trim());
        using var response = await httpClient.GetAsync($"users?email={encodedEmail}&exact=true", ct);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var users = await response.Content.ReadFromJsonAsync(
            KeycloakJsonContext.Default.ListKeycloakUserResponse,
            ct);
        var user = users?.FirstOrDefault(static u => !string.IsNullOrWhiteSpace(u.Id));
        if (user is null)
        {
            return null;
        }

        return new KeycloakUserSummary(user.Id!, user.Email ?? email.Trim(), user.Username ?? user.Email ?? string.Empty);
    }

    private static string? TryExtractUserId(Uri? locationHeader)
    {
        if (locationHeader is null)
        {
            return null;
        }

        var segments = locationHeader.Segments;
        return segments.Length == 0 ? null : segments[^1].Trim('/');
    }
}
