using System.Net;
using System.Net.Http.Json;
using Sentinel.Application.Auth.Models;
using Sentinel.Domain.Users;
using Sentinel.Security.Abstractions.Exceptions;
using Sentinel.Security.Abstractions.Identity;
using Sentinel.Security.Abstractions.Results;
using Sentinel.Keycloak;

namespace Sentinel.Infrastructure.Auth.Services;

internal sealed class KeycloakUserService(HttpClient httpClient, ILogger<KeycloakUserService> logger)
    : IIdentityRegistry, IIdentityProvider
{
    public Task<SecurityResult<string>> CreateUserAsync(
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

        return CreateUserInternalAsync(legacyRegistration, password, cancellationToken);
    }

    public async Task<SecurityResult<string>> CreateUserInternalAsync(UserRegistration registration, string password, CancellationToken ct)
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
                return SecurityResultFactory.Failure<string>(SecurityErrors.IdentityConflictMessage);
            }

            var error = await response.Content.ReadAsStringAsync(ct);
            logger.LogWarning("Failed to create Keycloak user. Status: {Status}. Body: {Body}",
                (int)response.StatusCode, error);
            return SecurityResultFactory.Failure<string>(SecurityErrors.IdentityCreationFailedMessage);
        }

        var userId = TryExtractUserId(response.Headers.Location);
        if (string.IsNullOrWhiteSpace(userId))
        {
            return SecurityResultFactory.Failure<string>(SecurityErrors.IdentityCreationFailedMessage);
        }

        return SecurityResultFactory.Create(userId);
    }

    public async Task<bool> SetEmailVerifiedAsync(string userId, bool verified, CancellationToken cancellationToken = default)
    {
        var payload = new KeycloakAdminUserUpdatePayload { EmailVerified = verified };

        using var response = await httpClient.PutAsJsonAsync(
            $"users/{Uri.EscapeDataString(userId)}",
            payload,
            KeycloakJsonContext.Default.KeycloakAdminUserUpdatePayload,
            cancellationToken);

        return response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NoContent;
    }

    public async Task<bool> DeleteUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.DeleteAsync($"users/{Uri.EscapeDataString(userId)}", cancellationToken);
        return response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NoContent;
    }

    public async Task<IdentityUserSummary?> GetUserByEmailAsync(string email, CancellationToken ct)
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

        return new IdentityUserSummary
        {
            Id = user.Id!,
            Email = user.Email ?? email.Trim(),
            Username = user.Username ?? user.Email ?? string.Empty
        };
    }

    public async Task<bool> UpdatePasswordAsync(string email, string newPassword, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(newPassword))
        {
            return false;
        }

        var user = await GetUserByEmailAsync(email, cancellationToken);
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
            $"users/{Uri.EscapeDataString(user.Id)}/reset-password",
            payload,
            KeycloakJsonContext.Default.KeycloakAdminPasswordResetPayload,
            cancellationToken);

        return response.IsSuccessStatusCode;
    }

    // Explicit interface implementation for IIdentityProvider
    async Task<IdentityUserSummary?> IIdentityProvider.GetUserByEmailAsync(string email, CancellationToken cancellationToken)
    {
        var summary = await GetUserByEmailAsync(email, cancellationToken);
        return summary is null ? null : new IdentityUserSummary
        {
            Id = summary.Id,
            Email = summary.Email,
            Username = summary.Username
        };
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
