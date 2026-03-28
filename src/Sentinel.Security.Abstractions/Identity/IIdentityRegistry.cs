using Sentinel.Security.Abstractions.Results;

namespace Sentinel.Security.Abstractions.Identity;

/// <summary>
///     Abstracts identity provider user lifecycle operations for application services.
///     All methods return SecurityResult for NuGet-first modularity: no provider-specific exceptions leak to consumers.
/// </summary>
public interface IIdentityRegistry
{
    /// <summary>
    ///     Creates a user in the configured identity provider and returns provider-specific user id.
    /// </summary>
    /// <returns>
    ///     Success with provider-specific user ID if user is created.
    ///     Failure with IdentityConflict error if user already exists.
    ///     Failure with IdentityCreationFailed if creation fails for other reasons.
    /// </returns>
    Task<SecurityResult<string>> CreateUserAsync(IdentityRegistration registration, string password,
        CancellationToken cancellationToken = default);
}
