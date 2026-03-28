using System.Security.Cryptography;

namespace Sentinel.Tests.Shared;

/// <summary>
///     Generates test cryptography keys for integration testing.
/// </summary>
public static class TestCryptographyHelper
{
    /// <summary>
    ///     Generates a valid test cryptography configuration that satisfies validation requirements.
    ///     Returns a dictionary with Cryptography:ActiveKeyId and Cryptography:KeyRing settings.
    /// </summary>
    public static Dictionary<string, string> GenerateTestCryptographyConfig()
    {
        // Generate a random 32-byte (256-bit) AES key
        var keyBytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(keyBytes);
        }

        var testKeyId = "test-key-2026-01";
        var testKeyBase64 = Convert.ToBase64String(keyBytes);

        // The configuration must be in a format that can be parsed by IConfiguration
        // We'll return it as a Dictionary that can be added to IConfigurationRoot via AddInMemoryCollection
        return new Dictionary<string, string>
        {
            { "Cryptography:ActiveKeyId", testKeyId },
            { $"Cryptography:KeyRing:{testKeyId}", testKeyBase64 }
        };
    }
}
