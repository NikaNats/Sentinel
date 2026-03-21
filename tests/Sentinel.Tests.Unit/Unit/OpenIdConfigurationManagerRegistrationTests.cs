using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Sentinel.Infrastructure.DependencyInjection;

namespace Sentinel.Tests.Unit;

public sealed class OpenIdConfigurationManagerRegistrationTests
{
    [Fact]
    public void AddSentinelCore_RegistersOpenIdConfigurationManagerAsSingleton()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Keycloak:Authority"] = "https://keycloak.example",
                ["Keycloak:Audience"] = "sentinel-api",
                ["Keycloak:Admin:ClientId"] = "admin-cli",
                ["Keycloak:Admin:ClientSecret"] = "secret"
            })
            .Build();

        var services = new ServiceCollection();
        _ = services.AddSentinelCore(configuration);
        using var provider = services.BuildServiceProvider();

        var first = provider.GetRequiredService<IConfigurationManager<OpenIdConnectConfiguration>>();
        var second = provider.GetRequiredService<IConfigurationManager<OpenIdConnectConfiguration>>();

        Assert.Same(first, second);
    }
}
