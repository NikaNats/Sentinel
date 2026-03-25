using Sentinel.Application.Common.Abstractions;
using AppJtiReplayCache = Sentinel.Application.Common.Abstractions.IJtiReplayCache;
using SecJtiReplayCache = Sentinel.Security.Abstractions.Replay.IJtiReplayCache;

namespace Sentinel.Tests.Shared.Fixtures;

/// <summary>
/// Adapter that bridges the Application-layer IJtiReplayCache interface to the Security-layer IJtiReplayCache.
/// </summary>
public sealed class JtiReplayCacheAdapter : AppJtiReplayCache
{
    private readonly SecJtiReplayCache _securityCache;
    private readonly TimeProvider _timeProvider;

    public JtiReplayCacheAdapter(SecJtiReplayCache securityCache, TimeProvider? timeProvider = null)
    {
        _securityCache = securityCache ?? throw new ArgumentNullException(nameof(securityCache));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Converts TimeSpan TTL to DateTimeOffset expiresAt and delegates to security cache.
    /// </summary>
    public async Task<bool> TryStoreIfNotExistsAsync(string jti, TimeSpan ttl, CancellationToken ct)
    {
        var expiresAt = _timeProvider.GetUtcNow() + ttl;
        return await _securityCache.TryMarkUsedAsync(jti, expiresAt, ct);
    }
}
