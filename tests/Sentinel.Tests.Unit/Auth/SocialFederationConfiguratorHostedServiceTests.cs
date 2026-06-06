using Microsoft.Extensions.Logging;
using Moq;
using Sentinel.Application.Auth.Models;
using Sentinel.Keycloak;
using Sentinel.Security.Abstractions.Identity;

namespace Sentinel.Tests.Unit.Auth;

public sealed class SocialFederationConfiguratorHostedServiceTests
{
    [Fact]
    public async Task StartAsync_WhenFederationIsDisabled_DoesNotCallProviders()
    {
        var provider = new Mock<IIdentityFederationProvider>(MockBehavior.Strict);
        var options = Microsoft.Extensions.Options.Options.Create(new SocialFederationOptions());
        var logger = new Mock<ILogger<SocialFederationConfiguratorHostedService>>();
        var sut = new SocialFederationConfiguratorHostedService(provider.Object, options, logger.Object);

        await sut.StartAsync(CancellationToken.None);

        provider.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task StartAsync_WhenProviderThrows_PropagatesException()
    {
        var provider = new Mock<IIdentityFederationProvider>(MockBehavior.Strict);
        provider
            .Setup(x => x.ConfigureGoogleProviderAsync(
                "google-client",
                "google-secret",
                It.IsAny<string>(),
                true,
                true,
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("boom"));

        var options = Microsoft.Extensions.Options.Options.Create(new SocialFederationOptions
        {
            Google = new GoogleFederationOptions
            {
                Enabled = true,
                ClientId = "google-client",
                ClientSecret = "google-secret"
            }
        });

        var logger = new Mock<ILogger<SocialFederationConfiguratorHostedService>>();
        var sut = new SocialFederationConfiguratorHostedService(provider.Object, options, logger.Object);

        await Assert.ThrowsAsync<HttpRequestException>(() => sut.StartAsync(CancellationToken.None));
    }
}
