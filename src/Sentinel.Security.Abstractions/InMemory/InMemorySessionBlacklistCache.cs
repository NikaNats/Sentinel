using System.Collections.Concurrent;
using Sentinel.Security.Abstractions.Session;

namespace Sentinel.Security.Abstractions.InMemory;

/// <summary>
/// Thread-safe in-memory session blacklist for testing.
/// </summary>
public sealed class InMemorySessionBlacklistCache : ISessionBlacklistCache
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _store = new();

    public Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        _store[sessionId] = expiresAt;
        return Task.CompletedTask;
    }

    public Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        if (_store.TryGetValue(sessionId, out var expiresAt))
        {
            // If not expired, it's still blacklisted
            if (expiresAt > DateTimeOffset.UtcNow)
            {
                return Task.FromResult(true);
            }

            // Expired, remove it
            _store.TryRemove(sessionId, out _);
        }

        return Task.FromResult(false);
    }

    public Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
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
