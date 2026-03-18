using Sentinel.Domain.Users;

namespace Sentinel.Application.Auth.Interfaces;

public interface IKeycloakAdminService
{
    Task<string> CreateUserAsync(UserRegistration registration, string password, CancellationToken ct);
    Task<bool> SetEmailVerifiedAsync(string keycloakUserId, bool verified, CancellationToken ct);
    Task<bool> DeleteUserAsync(string keycloakUserId, CancellationToken ct);
}
