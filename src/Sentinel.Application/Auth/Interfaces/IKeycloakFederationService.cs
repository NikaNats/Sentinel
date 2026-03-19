using Sentinel.Application.Auth.Models;

namespace Sentinel.Application.Auth.Interfaces;

public interface IKeycloakFederationService
{
    Task ConfigureGoogleProviderAsync(GoogleFederationOptions options, string firstBrokerLoginFlowAlias, CancellationToken ct);
    Task ConfigureGitHubProviderAsync(GitHubFederationOptions options, string firstBrokerLoginFlowAlias, CancellationToken ct);
}
