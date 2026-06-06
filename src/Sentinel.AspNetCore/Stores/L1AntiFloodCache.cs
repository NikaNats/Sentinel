using System.Collections.Concurrent;

namespace Sentinel.AspNetCore.Stores;

/// <summary>
///     L1 In-Memory Cache to protect Redis from L7 DoS attacks.
///     Remembers discredited JTIs or Thumbprints for a very short time (e.g., 3 seconds).
///     ✅ HIGH-ASSURANCE: Thread-safe, bounded-capacity, and self-pruning.
///     Prevents memory exhaustion attacks under randomized key floods.
/// </summary>
internal sealed class L1AntiFloodCache(TimeProvider timeProvider, TimeSpan ttl)
{
    private const int MaxCacheCapacity = 50000;

    private readonly ConcurrentDictionary<string, long> _shortTermBlacklist =
        new(Environment.ProcessorCount * 4, MaxCacheCapacity);

    private readonly long _ttlTicks = ttl.Ticks;

    public void RecordFailedAttempt(string identifier)
    {
        var nowTicks = timeProvider.GetUtcNow().Ticks;

        if (_shortTermBlacklist.Count >= MaxCacheCapacity)
        {
            PruneExpiredEntries(nowTicks);

            if (_shortTermBlacklist.Count >= MaxCacheCapacity)
            {
                _shortTermBlacklist.Clear();
            }
        }

        var expiration = nowTicks + _ttlTicks;
        _shortTermBlacklist[identifier] = expiration;
    }

    public bool IsTemporarilyBlacklisted(string identifier)
    {
        if (_shortTermBlacklist.TryGetValue(identifier, out var expirationTicks))
        {
            if (timeProvider.GetUtcNow().Ticks < expirationTicks)
            {
                return true;
            }

            _shortTermBlacklist.TryRemove(identifier, out _);
        }

        return false;
    }

    private void PruneExpiredEntries(long nowTicks)
    {
        foreach (var kvp in _shortTermBlacklist)
        {
            if (kvp.Value < nowTicks)
            {
                _shortTermBlacklist.TryRemove(kvp.Key, out _);
            }
        }
    }
}
