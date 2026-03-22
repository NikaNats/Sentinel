namespace Sentinel.Security.Abstractions.Identity;

/// <summary>
/// Abstracts common identity provider user operations (lookup, password update, revocation).
/// Implementations should be provider-agnostic (Keycloak, Auth0, etc.).
/// </summary>
public interface IIdentityProvider
{
    /// <summary>
    /// Creates a user in the configured identity provider and returns provider-specific user id.
    /// </summary>
    Task<string> CreateUserAsync(IdentityRegistration registration, string password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves user summary by email address.
    /// </summary>
    Task<IdentityUserSummary?> GetUserByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates user password in the identity provider.
    /// </summary>
    Task<bool> UpdatePasswordAsync(string email, string newPassword, CancellationToken cancellationToken = default);
}

/// <summary>
/// Summary of a user retrieved from the identity provider.
/// </summary>
public sealed class IdentityUserSummary
{
    public required string Id { get; init; }
    public required string Email { get; init; }
    public required string Username { get; init; }
}
