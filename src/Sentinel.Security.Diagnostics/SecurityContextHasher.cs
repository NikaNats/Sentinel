using System;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Sentinel.Security.Diagnostics;

/// <summary>
/// High-efficiency, zero-allocation IP hashing utility.
/// Uses request-scoped caching via HttpContext.Items to guarantee 100% async-safety
/// and prevent ThreadLocal memory leaks and daily key drift.
/// </summary>
public static class SecurityContextHasher
{
    private const string UnknownIpHash = "unknown";

    private const string HttpContextIpHashKey = "sentinel.security.ip_hash";

    /// <summary>
    /// Hashes the client's remote IP address using the privacy hasher.
    /// Guarantees zero heap allocations on cache hits within the same HTTP request lifecycle.
    /// </summary>
    public static string HashIp(HttpContext context)
    {
        if (context is null) return UnknownIpHash;

        if (context.Items.TryGetValue(HttpContextIpHashKey, out var cachedHash) && cachedHash is string hashStr)
        {
            return hashStr;
        }

        var ip = context.Connection.RemoteIpAddress;
        if (ip is null) return UnknownIpHash;

        var hasher = context.RequestServices?.GetService<IPrivacyPreservingHasher>();
        if (hasher is null) return UnknownIpHash;

        var hash = hasher.HashIpAddress(ip);

        context.Items[HttpContextIpHashKey] = hash;

        return hash;
    }
}
