using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Sentinel.Security.Diagnostics;

/// <summary>
/// High-efficiency, zero-allocation IP hashing utility.
/// Employs a thread-local L1 cache to guarantee 0 bytes allocated on cache hits.
/// </summary>
public static class SecurityContextHasher
{
    private const string UnknownIpHash = "unknown";
    
    // L1 Cache: prevents hashing the same IP multiple times during a single HTTP request
    private static readonly ThreadLocal<CacheEntry> ThreadLocalCache = new(static () => new CacheEntry());

    /// <summary>
    /// Hashes the client's Remote IP Address using the privacy hasher, with 0 heap allocations on cache hit.
    /// </summary>
    public static string HashIp(HttpContext context)
    {
        if (context is null) return UnknownIpHash;
        var ip = context.Connection.RemoteIpAddress;
        if (ip is null) return UnknownIpHash;

        var cache = ThreadLocalCache.Value!;
        if (ip.Equals(cache.LastIp) && cache.LastHash is not null)
        {
            return cache.LastHash; // 0-allocation cache hit
        }

        // Retrieve our new secure hasher from the DI container
        var hasher = context.RequestServices?.GetService<IPrivacyPreservingHasher>();
        if (hasher is null) return UnknownIpHash;

        var hash = hasher.HashIpAddress(ip);
        cache.LastIp = ip;
        cache.LastHash = hash;

        return hash;
    }

    private sealed class CacheEntry
    {
        public IPAddress? LastIp { get; set; }
        public string? LastHash { get; set; }
    }
}
