namespace Sentinel.Infrastructure.Auth;

public static class KeycloakOptionsExtensions
{
    public static TimeSpan ResolveSessionBlacklistTtl(this KeycloakOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var configuredSeconds = options.SsoSessionMaxLifespanSeconds > 0
            ? options.SsoSessionMaxLifespanSeconds
            : options.SessionMaxLifespanSeconds ?? 28_800;

        if (configuredSeconds <= 0)
        {
            configuredSeconds = 28_800;
        }

        return TimeSpan.FromSeconds(configuredSeconds);
    }
}
