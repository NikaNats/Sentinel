using System.Collections.Concurrent;

namespace Sentinel.AspNetCore.Stores;

/// <summary>
///     L1 In-Memory Cache acting as a first-line defense against L7 DoS attacks targeting Redis.
///     Temporarily stores discredited JTIs or Thumbprints with a short TTL (e.g., 3 seconds).
///     Implements thread-safe, lock-free O(1) amortized pruning to maintain optimal performance.
///     Minimizes CPU spikes and GC pressure even during high-volume flood attack scenarios.
/// </summary>
internal sealed class L1AntiFloodCache(TimeProvider timeProvider, TimeSpan ttl)
{
    private const int MaxCacheCapacity = 50000;
    private readonly ConcurrentQueue<(string Key, long Expiration)> _expiryQueue = new();

    private readonly ConcurrentDictionary<string, long> _shortTermBlacklist =
        new(Environment.ProcessorCount * 4, MaxCacheCapacity);

    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly long _ttlTicks = ttl.Ticks;
    private int _pruningActive;

    public void RecordFailedAttempt(string identifier)
    {
        var nowTicks = _timeProvider.GetUtcNow().Ticks;

        if (_shortTermBlacklist.Count >= MaxCacheCapacity)
        {
            if (Interlocked.CompareExchange(ref _pruningActive, 1, 0) == 0)
            {
                try
                {
                    PruneExpiredEntriesO1(nowTicks);
                }
                finally
                {
                    Interlocked.Exchange(ref _pruningActive, 0);
                }
            }

            while (_shortTermBlacklist.Count >= MaxCacheCapacity)
            {
                if (_expiryQueue.TryDequeue(out var oldest))
                {
                    _shortTermBlacklist.TryRemove(oldest.Key, out _);
                }
                else
                {
                    _shortTermBlacklist.Clear();
                    break;
                }
            }
        }

        var expiration = nowTicks + _ttlTicks;
        if (_shortTermBlacklist.TryAdd(identifier, expiration))
        {
            _expiryQueue.Enqueue((identifier, expiration));
        }
    }

    public bool IsTemporarilyBlacklisted(string identifier)
    {
        if (_shortTermBlacklist.TryGetValue(identifier, out var expirationTicks))
        {
            if (_timeProvider.GetUtcNow().Ticks < expirationTicks)
            {
                return true;
            }

            _shortTermBlacklist.TryRemove(identifier, out _);
        }

        return false;
    }

    private void PruneExpiredEntriesO1(long nowTicks)
    {
        while (_expiryQueue.TryPeek(out var oldest) && oldest.Expiration < nowTicks)
        {
            if (_expiryQueue.TryDequeue(out oldest))
            {
                if (_shortTermBlacklist.TryGetValue(oldest.Key, out var currentExp) && currentExp == oldest.Expiration)
                {
                    _shortTermBlacklist.TryRemove(oldest.Key, out _);
                }
            }
        }
    }
}
