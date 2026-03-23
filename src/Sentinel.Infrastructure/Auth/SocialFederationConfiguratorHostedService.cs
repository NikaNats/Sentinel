using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sentinel.Application.Auth.Models;
using Sentinel.Security.Abstractions.Identity;

namespace Sentinel.Infrastructure.Auth;

internal sealed class SocialFederationConfiguratorHostedService(
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
#pragma warning disable CA1031 // Intentional catch-all: startup federation configuration should not crash the host.
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to configure social federation providers.");
        }
#pragma warning restore CA1031
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _ = cancellationToken;
        return Task.CompletedTask;
    }
}
