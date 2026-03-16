namespace Sentinel.Infrastructure;

public static class FipsConfiguration
{
    private const string FipsProcPath = "/proc/sys/crypto/fips_enabled";

    public static void Apply()
    {
        AppContext.SetSwitch("Switch.System.Security.Cryptography.UseLegacyFipsThrow", false);

        if (IsFipsEnabled())
            Console.WriteLine("Sentinel API is running in FIPS-enabled mode.");
    }

    private static bool IsFipsEnabled() =>
        OperatingSystem.IsLinux()
        && File.Exists(FipsProcPath)
        && File.ReadAllText(FipsProcPath).Trim() == "1";
}
