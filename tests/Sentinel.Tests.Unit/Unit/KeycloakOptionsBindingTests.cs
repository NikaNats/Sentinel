using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sentinel.Keycloak;
using Sentinel.Keycloak.Extensions;
using Sentinel.Security.Abstractions.DependencyInjection;

namespace Sentinel.Tests.Unit.Unit;

public sealed class KeycloakOptionsBindingTests
{
    [Fact]
    public void AddKeycloakIntegration_BindsRootKeycloakSection()
    {
        var options = Resolve(services => services.AddKeycloakIntegration(new ConfigurationBuilder().Build()),
            ("Keycloak:Authority", "https://idp.example/realms/app"),
            ("Keycloak:Audience", "my-api"));

        Assert.Equal("https://idp.example/realms/app", options.Authority);
        Assert.Equal("my-api", options.Audience);
    }

    [Fact]
    public void LegacySentinelKeycloakSection_IsFallbackOnly()
    {
        var options = Resolve(services => services.AddKeycloakIntegration(new ConfigurationBuilder().Build()),
            ("Keycloak:Authority", "https://idp.example/realms/app"),
            ("Sentinel:Keycloak:Authority", "https://legacy.example/realms/app"),
            ("Sentinel:Keycloak:Audience", "legacy-api"));

        Assert.Equal("https://idp.example/realms/app", options.Authority);
        Assert.Equal("legacy-api", options.Audience);
    }

    [Fact]
    public void AddKeycloakAndAddKeycloakIntegration_RegisterOneBinding()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder().Build();
        _ = services.AddKeycloakIntegration(configuration);
        _ = new TestSecurityBuilder(services).AddKeycloak(configuration);
        _ = services.AddKeycloakIntegration(configuration);

        Assert.Single(services, d => d.ServiceType == typeof(IConfigureOptions<KeycloakOptions>));
    }

    private static KeycloakOptions Resolve(Action<IServiceCollection> register,
        params (string Key, string Value)[] values)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
            .Build();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        register(services);
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IOptions<KeycloakOptions>>().Value;
    }

    private sealed class TestSecurityBuilder(IServiceCollection services) : ISentinelSecurityBuilder
    {
        public IServiceCollection Services { get; } = services;
    }
}
