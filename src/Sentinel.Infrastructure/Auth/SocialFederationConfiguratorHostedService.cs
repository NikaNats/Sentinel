using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;

namespace Sentinel.Infrastructure.Auth;

public sealed class SocialFederationConfiguratorHostedService(
    IKeycloakFederationService keycloakFederationService,
    IOptions<SocialFederationOptions> options,
    ILogger<SocialFederationConfiguratorHostedService> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var federationOptions = options.Value;

        if (!federationOptions.Google.Enabled && !federationOptions.GitHub.Enabled)
        {
            return;
        }

        try
        {
            if (federationOptions.Google.Enabled)
            {
                await keycloakFederationService.ConfigureGoogleProviderAsync(
                    federationOptions.Google,
                    federationOptions.FirstBrokerLoginFlowAlias,
                    cancellationToken);
            }

            if (federationOptions.GitHub.Enabled)
            {
                await keycloakFederationService.ConfigureGitHubProviderAsync(
                    federationOptions.GitHub,
                    federationOptions.FirstBrokerLoginFlowAlias,
                    cancellationToken);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to configure social federation providers.");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _ = cancellationToken;
        return Task.CompletedTask;
    }
}
