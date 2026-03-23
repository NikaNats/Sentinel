namespace Sentinel.Security.Abstractions.Identity;

/// <summary>
/// Abstracts identity federation/social login provider configuration.
/// Implementations should be provider-agnostic (Keycloak, Auth0, Entra ID, etc.).
/// </summary>
public interface IIdentityFederationProvider
{
    /// <summary>
    /// Configures Google as an identity provider for social login.
    /// </summary>
    Task ConfigureGoogleProviderAsync(
        string clientId,
        string clientSecret,
        string firstBrokerLoginFlowAlias,
        bool trustEmail = true,
        bool storeToken = true,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Configures GitHub as an identity provider for social login.
    /// </summary>
    Task ConfigureGitHubProviderAsync(
        string clientId,
        string clientSecret,
        string firstBrokerLoginFlowAlias,
        bool trustEmail = true,
        bool storeToken = true,
        CancellationToken cancellationToken = default);
}
