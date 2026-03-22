using System.Collections.Concurrent;
using Sentinel.Security.Abstractions.Nonce;

namespace Sentinel.Security.Abstractions.InMemory;

/// <summary>
/// Thread-safe in-memory DPoP nonce store for testing.
/// </summary>
public sealed class InMemoryDpopNonceStore : IDpopNonceStore
{
    private readonly ConcurrentDictionary<string, (string Nonce, DateTimeOffset Expiry)> _store = new();

    public Task<string?> GetNonceAsync(string thumbprint, CancellationToken cancellationToken = default)
    {
        if (_store.TryGetValue(thumbprint, out var entry))
        {
            if (entry.Expiry > DateTimeOffset.UtcNow)
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
        var now = DateTimeOffset.UtcNow;
        foreach (var kvp in _store)
        {
            if (kvp.Value.Expiry <= now)
            {
                _store.TryRemove(kvp.Key, out _);
            }
        }

        return Task.CompletedTask;
    }
}
