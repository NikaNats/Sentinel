namespace Sentinel.Keycloak;

public static class KeycloakOptionsExtensions
{
    public static TimeSpan ResolveSessionBlacklistTtl(this KeycloakOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var configuredSeconds = options.SsoSessionMaxLifespanSeconds > 0
            ? options.SsoSessionMaxLifespanSeconds
            : 28_800; // Default 8 hours

        return TimeSpan.FromSeconds(configuredSeconds);
    }
}
