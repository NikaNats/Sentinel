using System.Collections.Concurrent;
using Sentinel.Security.Abstractions.Nonce;

namespace Sentinel.Security.Abstractions.InMemory;

/// <summary>
/// Thread-safe in-memory DPoP nonce store for testing.
/// </summary>
public sealed class InMemoryDpopNonceStore : IDpopNonceStore
{
    private readonly ConcurrentDictionary<string, (string Nonce, DateTimeOffset Expiry)> _store = new();
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryDpopNonceStore"/> class.
    /// </summary>
    /// <param name="timeProvider">Optional time provider for testing. Defaults to <see cref="TimeProvider.System"/>.</param>
    public InMemoryDpopNonceStore(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public Task<string?> GetNonceAsync(string thumbprint, CancellationToken cancellationToken = default)
    {
        if (_store.TryGetValue(thumbprint, out var entry))
        {
            if (entry.Expiry > _timeProvider.GetUtcNow())
            {
                return Task.FromResult((string?)entry.Nonce);
            }

            // Expired, remove it
            _store.TryRemove(thumbprint, out _);
        }

        return Task.FromResult((string?)null);
    }

    public Task SetNonceAsync(string thumbprint, string nonce, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        _store[thumbprint] = (nonce, expiresAt);
        return Task.CompletedTask;
    }

    public Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();
        foreach (var kvp in _store)
        {
            if (kvp.Value.Expiry <= now)
            {
                _store.TryRemove(kvp.Key, out _);
            }
        }

        return Task.CompletedTask;
    }

    public Task<bool> ConsumeNonceIfMatchesAsync(string thumbprint, string expectedNonce, CancellationToken cancellationToken = default)
    {
        if (_store.TryGetValue(thumbprint, out var entry))
        {
            // Check if expired
            if (entry.Expiry <= _timeProvider.GetUtcNow())
            {
                _store.TryRemove(thumbprint, out _);
                return Task.FromResult(false);
            }

            // Check if nonce matches
            if (entry.Nonce == expectedNonce)
            {
                // Atomically remove it
                if (_store.TryRemove(thumbprint, out _))
                {
                    return Task.FromResult(true);
                }
            }
        }

        return Task.FromResult(false);
    }
}
