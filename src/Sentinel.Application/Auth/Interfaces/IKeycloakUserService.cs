using Sentinel.Domain.Users;
using Sentinel.Security.Abstractions.Identity;

namespace Sentinel.Application.Auth.Interfaces;

public interface IKeycloakUserService
{
    Task<string> CreateUserAsync(UserRegistration registration, string password, CancellationToken ct);
    Task<bool> SetEmailVerifiedAsync(string keycloakUserId, bool verified, CancellationToken ct);
    Task<bool> DeleteUserAsync(string keycloakUserId, CancellationToken ct);
    Task<IdentityUserSummary?> GetUserByEmailAsync(string email, CancellationToken ct);
}
