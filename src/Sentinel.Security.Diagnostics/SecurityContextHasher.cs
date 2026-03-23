namespace Sentinel.Security.Diagnostics;

/// <summary>
/// Hashes HTTP context information (like IP addresses) for use in security events and logs.
/// Prevents direct logging of PII while maintaining correlation capability.
/// </summary>
public static class SecurityContextHasher
{
    /// <summary>
    /// Hashes the remote IP address from an HttpContext using SHA-256.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>Hex-encoded SHA-256 hash of the remote IP address.</returns>
    public static string HashIp(HttpContext context)
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(ip));
        return Convert.ToHexString(bytes);
    }
}
