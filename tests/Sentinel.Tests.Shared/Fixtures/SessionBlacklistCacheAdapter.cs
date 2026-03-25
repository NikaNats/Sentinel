using Sentinel.Security.Abstractions.Session;
using AppSessionBlacklistCache = Sentinel.Application.Common.Abstractions.ISessionBlacklistCache;
using SecSessionBlacklistCache = Sentinel.Security.Abstractions.Session.ISessionBlacklistCache;

namespace Sentinel.Tests.Shared.Fixtures;

/// <summary>
/// Adapter that bridges the Application-layer ISessionBlacklistCache interface to the Security-layer ISessionBlacklistCache.
/// </summary>
public sealed class SessionBlacklistCacheAdapter : AppSessionBlacklistCache
{
    private readonly SecSessionBlacklistCache _securityCache;
    private readonly TimeProvider _timeProvider;

    public SessionBlacklistCacheAdapter(SecSessionBlacklistCache securityCache, TimeProvider? timeProvider = null)
    {
        _securityCache = securityCache ?? throw new ArgumentNullException(nameof(securityCache));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Converts TimeSpan TTL to DateTimeOffset expiresAt and delegates to security cache.
    /// </summary>
    public async Task BlacklistSessionAsync(string sessionId, TimeSpan ttl, CancellationToken ct)
    {
        var expiresAt = _timeProvider.GetUtcNow() + ttl;
        await _securityCache.BlacklistSessionAsync(sessionId, expiresAt, ct);
    }

    /// <summary>
    /// Converts Task&lt;bool&gt; to ValueTask&lt;bool&gt; from security cache's IsBlacklistedAsync.
    /// </summary>
    public async ValueTask<bool> IsSessionBlacklistedAsync(string sessionId, CancellationToken ct)
    {
        return await _securityCache.IsBlacklistedAsync(sessionId, ct);
    }
}
