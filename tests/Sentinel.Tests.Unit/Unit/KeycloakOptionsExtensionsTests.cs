using Sentinel.Infrastructure.Auth;
using Sentinel.Keycloak;

namespace Sentinel.Tests.Unit;

public sealed class KeycloakOptionsExtensionsTests
{
    [Fact]
    public void ResolveSessionBlacklistTtl_WhenSsoLifespanConfigured_UsesSsoValue()
    {
        var options = new KeycloakOptions
        {
            Authority = "https://keycloak.example",
            Audience = "sentinel-api",
            SsoSessionMaxLifespanSeconds = 7200,
            SessionMaxLifespanSeconds = 3600
        };

        var ttl = options.ResolveSessionBlacklistTtl();

        Assert.Equal(TimeSpan.FromSeconds(7200), ttl);
    }

    [Fact]
    public void ResolveSessionBlacklistTtl_WhenSsoInvalid_UsesLegacySessionValue()
    {
        var options = new KeycloakOptions
        {
            Authority = "https://keycloak.example",
            Audience = "sentinel-api",
            SsoSessionMaxLifespanSeconds = 0,
            SessionMaxLifespanSeconds = 1800
        };

        var ttl = options.ResolveSessionBlacklistTtl();

        Assert.Equal(TimeSpan.FromSeconds(1800), ttl);
    }

    [Fact]
    public void ResolveSessionBlacklistTtl_WhenAllValuesInvalid_UsesDefault()
    {
        var options = new KeycloakOptions
        {
            Authority = "https://keycloak.example",
            Audience = "sentinel-api",
            SsoSessionMaxLifespanSeconds = -1,
            SessionMaxLifespanSeconds = 0
        };

        var ttl = options.ResolveSessionBlacklistTtl();

        Assert.Equal(TimeSpan.FromSeconds(28_800), ttl);
    }
}
