using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Sentinel.Security.Diagnostics;

/// <summary>
/// Cryptographically secure context hasher preventing IPv4 rainbow table attacks.
/// </summary>
public static class SecurityContextHasher
{
    // High-entropy static salt per application lifecycle.
    // In multi-node deployments, replace fallback generation with centralized vault loading.
    private static readonly byte[] ClusterSalt = GenerateOrLoadClusterSalt();

    public static string HashIp(HttpContext context)
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var ipBytes = Encoding.UTF8.GetBytes(ip);

        var hashBytes = HMACSHA256.HashData(ClusterSalt, ipBytes);
        return Convert.ToHexString(hashBytes);
    }

    private static byte[] GenerateOrLoadClusterSalt()
    {
        var salt = new byte[32];
        RandomNumberGenerator.Fill(salt);
        return salt;
    }
}
