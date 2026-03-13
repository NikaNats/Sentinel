using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Testcontainers.Keycloak;
using Testcontainers.Redis;
using Xunit;

namespace Sentinel.Tests.Integration.Fixtures;

public sealed class SentinelApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly KeycloakContainer keycloakContainer;
    private readonly RedisContainer redisContainer;

    public SentinelApiFactory()
    {
        var realmPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../../infra/keycloak/realms/sentinel.json"));

        keycloakContainer = new KeycloakBuilder("quay.io/keycloak/keycloak:26.1")
            .WithEnvironment("KC_FEATURES", "dpop,par,fips:preview")
            .WithResourceMapping(realmPath, "/opt/keycloak/data/import/sentinel.json")
            .WithCommand("start-dev", "--import-realm")
            .Build();

        redisContainer = new RedisBuilder("redis:7.4-alpine").Build();
    }

    public string KeycloakRealmAuthority => $"{keycloakContainer.GetBaseAddress()}realms/sentinel";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Keycloak:Authority"] = KeycloakRealmAuthority,
                ["ConnectionStrings:Redis"] = redisContainer.GetConnectionString(),
                ["FeatureFlags:Auth:DpopFlow"] = "true"
            });
        });
    }

    public async Task InitializeAsync()
    {
        await redisContainer.StartAsync();
        await keycloakContainer.StartAsync();
    }

    async Task IAsyncLifetime.DisposeAsync()
    {
        await keycloakContainer.DisposeAsync();
        await redisContainer.DisposeAsync();
        await base.DisposeAsync();
    }
}
