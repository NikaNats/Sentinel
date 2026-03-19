namespace Sentinel.Application.Auth.Interfaces;

public interface IKeycloakProfileService
{
    Task<bool> UpdateProfileAsync(string subjectId, string? displayName, CancellationToken ct);
    Task<bool> UpdatePasswordAsync(string email, string newPassword, CancellationToken ct);
    Task<bool> VerifyUserPasswordAsync(string usernameOrEmail, string currentPassword, CancellationToken ct);
}
