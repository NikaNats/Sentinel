using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Infrastructure;

public static class FipsConfiguration
{
    private const string FipsProcPath = "/proc/sys/crypto/fips_enabled";

    public static void Apply(ILogger logger)
    {
        AppContext.SetSwitch("Switch.System.Security.Cryptography.UseLegacyFipsThrow", false);

        if (IsFipsEnabled())
        {
            logger.LogInformation("security:fips_mode_enabled Sentinel API is running in FIPS-enabled mode.");
        }
    }

    public static void Apply()
    {
        Apply(NullLogger.Instance);
    }

    private static bool IsFipsEnabled() =>
        OperatingSystem.IsLinux()
        && File.Exists(FipsProcPath)
        && File.ReadAllText(FipsProcPath).Trim() == "1";
}
