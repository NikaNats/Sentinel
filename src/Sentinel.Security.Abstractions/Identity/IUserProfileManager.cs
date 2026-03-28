namespace Sentinel.Security.Abstractions.Identity;

/// <summary>
///     Abstracts user profile management operations.
///     Implementations should be provider-agnostic (Keycloak, Auth0, Entra ID, etc.).
/// </summary>
public interface IUserProfileManager
{
    /// <summary>
    ///     Updates the user's display name/full name in the identity provider.
    /// </summary>
    Task<bool> UpdateProfileAsync(string subjectId, string? displayName, CancellationToken cancellationToken = default);
}
