using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Sentinel.Sample.MinimalApi;

// FAPI 2.0 / NIST SP 800-63B dual-partition CHAINED rate limiting - shared state and
// builders backing the GlobalLimiter wired in Program.cs.
//
// Dimension 1 (primary quota): authenticated traffic is keyed by the token's `sub`
// claim (parsed pre-auth, WITHOUT signature verification - validity is enforced
// downstream by the DPoP and JWT bearer middlewares), so rotating or spoofing
// X-Forwarded-For cannot open fresh partitions for a valid token holder. Anonymous
// or malformed traffic falls back to a per-source-address window.
//
// Dimension 2 (network floor): EVERY request additionally consumes a per-source-
// address permit, bounding aggregate traffic even when many distinct identities
// originate from one host, so per-identity quotas cannot be multiplied into a
// DoS amplifier.
//
// Both dimensions chain via PartitionedRateLimiter.CreateChained: a request is
// admitted only when BOTH windows grant; a rejection at either dimension releases
// any permits held at the other and surfaces as 429 Too Many Requests.
//
// NOTE: the runtime caches one window per distinct identity/source key (unbounded).
// Production hosts exposed to identity/IP rotation attacks should replace this
// in-memory limiter with a distributed limiter (e.g. Redis-backed) via the same
// GlobalLimiter abstraction.
internal static class DualPartitionRateLimiting
{
    private const int PrimaryPermitLimit = 20;
    private static readonly TimeSpan PrimaryWindow = TimeSpan.FromSeconds(10);
    private const int PrimaryQueueLimit = 5;

    private const int FloorPermitLimit = 100;
    private static readonly TimeSpan FloorWindow = TimeSpan.FromSeconds(10);
    private const int FloorQueueLimit = 2;

    /// <summary>
    ///     Paths guarded by the dual-partition quota. The global chained limiter grants
    ///     every other path instantly so health probes and docs stay unthrottled.
    /// </summary>
    private static readonly HashSet<string> LimitedPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/v1/profile",
        "/v1/test/protected"
    };

    public static bool IsLimitedPath(HttpContext httpContext) =>
        LimitedPaths.Contains(httpContext.Request.Path.Value?.TrimEnd('/') ?? string.Empty);

    public static PartitionedRateLimiter<HttpContext> BuildPrimaryQuota() =>
        PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        {
            if (!IsLimitedPath(httpContext))
            {
                return RateLimitPartition.GetNoLimiter("unlimited");
            }

            var subject = TryResolveSubject(httpContext);
            return subject is not null
                ? RateLimitPartition.GetSlidingWindowLimiter($"sub:{subject}", _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = PrimaryPermitLimit,
                    Window = PrimaryWindow,
                    SegmentsPerWindow = 2,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = PrimaryQueueLimit
                })
                : RateLimitPartition.GetSlidingWindowLimiter($"ip:{GetRemoteIp(httpContext)}", _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = PrimaryPermitLimit,
                    Window = PrimaryWindow,
                    SegmentsPerWindow = 2,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = PrimaryQueueLimit
                });
        });

    public static PartitionedRateLimiter<HttpContext> BuildNetworkFloor() =>
        PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        {
            if (!IsLimitedPath(httpContext))
            {
                return RateLimitPartition.GetNoLimiter("unlimited");
            }

            return RateLimitPartition.GetSlidingWindowLimiter($"ip:{GetRemoteIp(httpContext)}", _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = FloorPermitLimit,
                Window = FloorWindow,
                SegmentsPerWindow = 2,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = FloorQueueLimit
            });
        });

    private static string GetRemoteIp(HttpContext httpContext) =>
        httpContext.Connection.RemoteIpAddress?.ToString() ?? "anonymous";

    private static string? TryResolveSubject(HttpContext context)
    {
        // 1. Prefer the authenticated principal when authentication already ran.
        var sub = context.User.FindFirst("sub")?.Value;
        if (!string.IsNullOrWhiteSpace(sub))
        {
            return sub;
        }

        // 2. Pre-authentication parsing: read `sub` straight from the presented JWT
        //    without verifying its signature (UseRateLimiter runs before UseAuthentication).
        //    A spoofed value only buys the attacker an isolated partition for a request
        //    that fails signature validation downstream anyway.
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authHeader))
        {
            return null;
        }

        string? rawToken = null;
        if (authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
        {
            rawToken = authHeader["DPoP ".Length..].Trim();
        }
        else if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            rawToken = authHeader["Bearer ".Length..].Trim();
        }

        if (string.IsNullOrWhiteSpace(rawToken))
        {
            return null;
        }

        try
        {
            var handler = new JsonWebTokenHandler();
            if (!handler.CanReadToken(rawToken))
            {
                return null;
            }

            var jwt = handler.ReadJsonWebToken(rawToken);
            var tokenSub = jwt.Subject ?? jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            return string.IsNullOrWhiteSpace(tokenSub) ? null : tokenSub;
        }
        catch
        {
            // Malformed tokens fall back to IP-based partitioning.
            return null;
        }
    }
}
