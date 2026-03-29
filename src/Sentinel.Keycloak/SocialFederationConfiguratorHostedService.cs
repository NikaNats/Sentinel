using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sentinel.Application.Auth.Models;
using Sentinel.Security.Abstractions.Identity;

namespace Sentinel.Keycloak;

public sealed class SocialFederationConfiguratorHostedService(
    IIdentityFederationProvider federationProvider,
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
                await federationProvider.ConfigureGoogleProviderAsync(
                    federationOptions.Google.ClientId,
                    federationOptions.Google.ClientSecret,
                    federationOptions.FirstBrokerLoginFlowAlias,
                    federationOptions.Google.TrustEmail,
                    federationOptions.Google.StoreToken,
                    cancellationToken);
            }

            if (federationOptions.GitHub.Enabled)
            {
                await federationProvider.ConfigureGitHubProviderAsync(
                    federationOptions.GitHub.ClientId,
                    federationOptions.GitHub.ClientSecret,
                    federationOptions.FirstBrokerLoginFlowAlias,
                    federationOptions.GitHub.TrustEmail,
                    federationOptions.GitHub.StoreToken,
                    cancellationToken);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogCritical(ex,
                "Failed to configure social federation providers during startup. Aborting host startup.");
            throw;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _ = cancellationToken;
        return Task.CompletedTask;
    }
}
