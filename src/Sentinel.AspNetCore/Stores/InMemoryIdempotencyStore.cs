using System.Collections.Concurrent;
using Sentinel.Security.Abstractions.Idempotency;

namespace Sentinel.AspNetCore.Stores;

/// <summary>
///     In-memory idempotency store for hosts that do not configure a distributed backend.
/// </summary>
internal sealed class InMemoryIdempotencyStore(TimeProvider? timeProvider = null) : IIdempotencyStore
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<(IdempotencyAcquireResult State, CachedHttpResponse? Response)> TryAcquireAsync(
        string key,
        TimeSpan inProgressTtl,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        _ = cancellationToken;

        var now = _timeProvider.GetUtcNow();
        PruneIfExpired(key, now);

        if (_entries.TryGetValue(key, out var existing) && existing.State == IdempotencyAcquireResult.Completed)
        {
            return (IdempotencyAcquireResult.Completed, existing.Response);
        }

        var added = _entries.TryAdd(key, new Entry(IdempotencyAcquireResult.InProgress, null, now + inProgressTtl));
        if (added)
        {
            return (IdempotencyAcquireResult.Acquired, null);
        }

        if (_entries.TryGetValue(key, out existing) && existing.State == IdempotencyAcquireResult.Completed)
        {
            return (IdempotencyAcquireResult.Completed, existing.Response);
        }

        var reacquired =
            _entries.TryAdd(key, new Entry(IdempotencyAcquireResult.InProgress, null, now + inProgressTtl));
        return reacquired
            ? (IdempotencyAcquireResult.Acquired, null)
            : (IdempotencyAcquireResult.InProgress, null);
    }

    public Task MarkCompletedAsync(
        string key,
        CachedHttpResponse response,
        TimeSpan completedTtl,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        _ = cancellationToken;

        var now = _timeProvider.GetUtcNow();
        _entries[key] = new Entry(IdempotencyAcquireResult.Completed, response, now + completedTtl);
        return Task.CompletedTask;
    }

    public Task ReleaseAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        _ = cancellationToken;

        _ = _entries.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    private void PruneIfExpired(string key, DateTimeOffset now)
    {
        if (_entries.TryGetValue(key, out var existing) && existing.ExpiresAt <= now)
        {
            _ = _entries.TryRemove(key, out _);
        }
    }

    private sealed record Entry(IdempotencyAcquireResult State, CachedHttpResponse? Response, DateTimeOffset ExpiresAt);
}
