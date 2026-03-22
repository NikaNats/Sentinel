namespace Sentinel.Security.Abstractions.Identity;

/// <summary>
/// Abstracts identity provider user lifecycle operations for application services.
/// </summary>
public interface IIdentityRegistry
{
    /// <summary>
    /// Creates a user in the configured identity provider and returns provider-specific user id.
    /// </summary>
    Task<string> CreateUserAsync(IdentityRegistration registration, string password, CancellationToken cancellationToken = default);
}
