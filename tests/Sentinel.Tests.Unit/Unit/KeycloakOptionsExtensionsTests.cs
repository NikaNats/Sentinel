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
            SsoSessionMaxLifespanSeconds = 7200
        };

        var ttl = options.ResolveSessionBlacklistTtl();

        Assert.Equal(TimeSpan.FromSeconds(7200), ttl);
    }

    [Fact]
    public void ResolveSessionBlacklistTtl_WhenSsoInvalid_UsesDefault()
    {
        var options = new KeycloakOptions
        {
            Authority = "https://keycloak.example",
            Audience = "sentinel-api",
            SsoSessionMaxLifespanSeconds = 0
        };

        var ttl = options.ResolveSessionBlacklistTtl();

        Assert.Equal(TimeSpan.FromSeconds(28_800), ttl);
    }

    [Fact]
    public void ResolveSessionBlacklistTtl_WhenAllValuesInvalid_UsesDefault()
    {
        var options = new KeycloakOptions
        {
            Authority = "https://keycloak.example",
            Audience = "sentinel-api",
            SsoSessionMaxLifespanSeconds = -1
        };

        var ttl = options.ResolveSessionBlacklistTtl();

        Assert.Equal(TimeSpan.FromSeconds(28_800), ttl);
    }
}
