using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.AspNetCore.Http;

namespace Sentinel.Security.Diagnostics;

/// <summary>
/// High-efficiency, zero-allocation IP hashing utility.
/// Employs a thread-local L1 cache to guarantee 0 bytes allocated on cache hits.
/// </summary>
public static class SecurityContextHasher
{
    private const string UnknownIpHash = "unknown";

    private static readonly ThreadLocal<CacheEntry> ThreadLocalCache = new(static () => new CacheEntry());
    private static readonly byte[] Salt = Encoding.UTF8.GetBytes("sentinel-ip-salt");

    /// <summary>
    /// Hashes the client's Remote IP Address using HMAC-SHA256 with 0 heap allocations on cache hit.
    /// </summary>
    public static string HashIp(HttpContext context)
    {
        if (context is null)
        {
            return UnknownIpHash;
        }

        var ip = context.Connection.RemoteIpAddress;
        if (ip is null)
        {
            return UnknownIpHash;
        }

        var cache = ThreadLocalCache.Value!;
        var cachedIp = cache.LastIp;

        if ((ReferenceEquals(cachedIp, ip) || (cachedIp is not null && cachedIp.Equals(ip))) &&
            cache.LastHash is { } cachedHash)
        {
            return cachedHash;
        }

        return HashAndCacheIp(ip, cache);
    }

    private static string HashAndCacheIp(IPAddress ip, CacheEntry cache)
    {
        Span<byte> ipBytes = stackalloc byte[16];
        if (!ip.TryWriteBytes(ipBytes, out var bytesWritten))
        {
            return UnknownIpHash;
        }

        Span<byte> hashBytes = stackalloc byte[32];
        HMACSHA256.HashData(Salt, ipBytes.Slice(0, bytesWritten), hashBytes);

        var state = new HashState
        {
            Part1 = BitConverter.ToUInt64(hashBytes.Slice(0, 8)),
            Part2 = BitConverter.ToUInt64(hashBytes.Slice(8, 8)),
            Part3 = BitConverter.ToUInt64(hashBytes.Slice(16, 8)),
            Part4 = BitConverter.ToUInt64(hashBytes.Slice(24, 8))
        };

        var hashString = string.Create(64, state, static (span, s) =>
        {
            Span<byte> buffer = stackalloc byte[32];
            BitConverter.TryWriteBytes(buffer.Slice(0, 8), s.Part1);
            BitConverter.TryWriteBytes(buffer.Slice(8, 8), s.Part2);
            BitConverter.TryWriteBytes(buffer.Slice(16, 8), s.Part3);
            BitConverter.TryWriteBytes(buffer.Slice(24, 8), s.Part4);

            for (var i = 0; i < 32; i++)
            {
                var value = buffer[i];
                span[i * 2] = GetHexChar(value >> 4);
                span[i * 2 + 1] = GetHexChar(value & 0x0F);
            }
        });

        cache.LastIp = ip;
        cache.LastHash = hashString;

        return hashString;
    }

    private static char GetHexChar(int value)
    {
        return value < 10 ? (char)('0' + value) : (char)('A' + (value - 10));
    }

    private struct HashState
    {
        public ulong Part1;
        public ulong Part2;
        public ulong Part3;
        public ulong Part4;
    }

    private sealed class CacheEntry
    {
        public IPAddress? LastIp { get; set; }
        public string? LastHash { get; set; }
    }
}
