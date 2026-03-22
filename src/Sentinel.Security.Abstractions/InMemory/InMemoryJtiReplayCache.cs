using System.Collections.Concurrent;
using Sentinel.Security.Abstractions.Replay;

namespace Sentinel.Security.Abstractions.InMemory;

/// <summary>
/// Thread-safe in-memory JTI replay cache for testing and simple deployments.
/// Uses <see cref="ConcurrentDictionary{TKey,TValue}"/> — no external deps.
/// NOT suitable for multi-instance deployments (no shared state).
/// </summary>
public sealed class InMemoryJtiReplayCache : IJtiReplayCache
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _store = new();
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryJtiReplayCache"/> class.
    /// </summary>
    /// <param name="timeProvider">Optional time provider for testing. Defaults to <see cref="TimeProvider.System"/>.</param>
    public InMemoryJtiReplayCache(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public Task<bool> TryMarkUsedAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        // Try to add the JTI — if it's already in the store, return false (replay detected)
        bool isNew = _store.TryAdd(jti, expiresAt);
        return Task.FromResult(isNew);
    }

    public Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();
        foreach (var kvp in _store)
        {
            if (kvp.Value <= now)
            {
                _store.TryRemove(kvp.Key, out _);
            }
        }

        return Task.CompletedTask;
    }
}
