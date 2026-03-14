using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Infrastructure.Telemetry;

public static class SecurityContextHasher
{
    public static string HashIp(HttpContext context)
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(ip));
        return Convert.ToHexString(bytes);
    }
}
