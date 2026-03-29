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

    public Task<IdempotencyAcquireResult> TryAcquireAsync(
        string key,
        TimeSpan inProgressTtl,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        _ = cancellationToken;

        var now = _timeProvider.GetUtcNow();
        PruneIfExpired(key, now);

        var added = _entries.TryAdd(key, new Entry(IdempotencyAcquireResult.InProgress, now + inProgressTtl));
        if (added)
        {
            return Task.FromResult(IdempotencyAcquireResult.Acquired);
        }

        if (_entries.TryGetValue(key, out var existing))
        {
            return Task.FromResult(existing.State == IdempotencyAcquireResult.Completed
                ? IdempotencyAcquireResult.Completed
                : IdempotencyAcquireResult.InProgress);
        }

        // Rare race where key was removed between add/check attempts.
        var reacquired = _entries.TryAdd(key, new Entry(IdempotencyAcquireResult.InProgress, now + inProgressTtl));
        return Task.FromResult(reacquired
            ? IdempotencyAcquireResult.Acquired
            : IdempotencyAcquireResult.InProgress);
    }

    public Task MarkCompletedAsync(string key, TimeSpan completedTtl, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        _ = cancellationToken;

        var now = _timeProvider.GetUtcNow();
        _entries[key] = new Entry(IdempotencyAcquireResult.Completed, now + completedTtl);
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

    private sealed record Entry(IdempotencyAcquireResult State, DateTimeOffset ExpiresAt);
}
