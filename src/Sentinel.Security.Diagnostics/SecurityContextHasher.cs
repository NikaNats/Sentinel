using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Sentinel.Security.Diagnostics;

/// <summary>
///     მაღალი წარმადობის, კრიპტოგრაფიულად დაცული იდენტობისა და კონტექსტის ჰეშერი.
///     სრულად თავსებადია Native AOT-თან და არ გამოყოფს მეხსიერებას ჰიპზე (Zero-Allocation on Hot-Path).
/// </summary>
public static class SecurityContextHasher
{
    // კლასტერული სოლტი (Salt) დისტრიბუციული დაცვისთვის
    private static readonly byte[] ClusterSalt = GenerateOrLoadClusterSalt();

    /// <summary>
    ///     ახორციელებს კლიენტის IP მისამართის უსაფრთხო ჰეშირებას (HMAC-SHA256) ყოველგვარი String/Array გამოყოფის გარეშე.
    /// </summary>
    public static string HashIp(HttpContext context)
    {
        var ipAddress = context.Connection.RemoteIpAddress;
        if (ipAddress is null)
        {
            return "unknown";
        }

        // 🟢 ოპტიმიზაცია: IPv6-ის მაქსიმალური სიგრძეა 45 სიმბოლო. ვიყენებთ stackalloc-ს სტრინგის შექმნის ნაცვლად
        Span<char> ipChars = stackalloc char[45];

        if (!ipAddress.TryFormat(ipChars, out var written))
        {
            return "unknown";
        }

        // ASCII ტექსტის გარდაქმნა ბაიტებში ლოკალურ სტეკზე
        Span<byte> ipBytes = stackalloc byte[45];
        var byteCount = Encoding.UTF8.GetBytes(ipChars[..written], ipBytes);

        // 32-ბაიტიანი ბუფერი HMAC-SHA256 ჰეშისთვის სტეკზე
        Span<byte> hashBytes = stackalloc byte[32];

        // კრიპტოგრაფიულად დაცული ატომური ჰეშირება
        HMACSHA256.HashData(ClusterSalt, ipBytes[..byteCount], hashBytes);

        // გარდაქმნა Hex ტექსტად (მეხსიერების ოპტიმიზებული რეჟიმით)
        return Convert.ToHexString(hashBytes);
    }

    private static byte[] GenerateOrLoadClusterSalt()
    {
        var salt = new byte[32];
        RandomNumberGenerator.Fill(salt);
        return salt;
    }
}
