using Sentinel.Domain.Users;
using Sentinel.Application.Auth.Models;

namespace Sentinel.Application.Auth.Interfaces;

public interface IKeycloakAdminService
{
    Task<string> CreateUserAsync(UserRegistration registration, string password, CancellationToken ct);
    Task<bool> SetEmailVerifiedAsync(string keycloakUserId, bool verified, CancellationToken ct);
    Task<bool> DeleteUserAsync(string keycloakUserId, CancellationToken ct);
    Task<KeycloakUserSummary?> GetUserByEmailAsync(string email, CancellationToken ct);
    Task<bool> UpdateProfileAsync(string subjectId, string? displayName, CancellationToken ct);
    Task<bool> UpdatePasswordAsync(string email, string newPassword, CancellationToken ct);
    Task<bool> VerifyUserPasswordAsync(string usernameOrEmail, string currentPassword, CancellationToken ct);
    Task ConfigureGoogleProviderAsync(GoogleFederationOptions options, string firstBrokerLoginFlowAlias, CancellationToken ct);
    Task ConfigureGitHubProviderAsync(GitHubFederationOptions options, string firstBrokerLoginFlowAlias, CancellationToken ct);
}
