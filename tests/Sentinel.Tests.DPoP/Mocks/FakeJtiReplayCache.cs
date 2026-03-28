using System.Collections.Concurrent;
using Sentinel.Security.Abstractions.Replay;

namespace Sentinel.Tests.DPoP.Mocks;

/// <summary>
/// Simple in-memory mock implementation of IJtiReplayCache for testing.
/// </summary>
public sealed class FakeJtiReplayCache : IJtiReplayCache
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _usedJtis = new();
    private bool _shouldFail;
    private string? _nextJti;

    /// <summary>
    /// Sets whether the cache should fail on the next call.
    /// </summary>
    public void SetShouldFail(bool fail)
    {
        _shouldFail = fail;
    }

    /// <summary>
    /// Expects the next call to be for a specific JTI.
    /// </summary>
    public void ExpectNextJti(string? jti)
    {
        _nextJti = jti;
    }

    /// <summary>
    /// Tries to mark a JTI as used.
    /// </summary>
    public async Task<bool> TryMarkUsedAsync(
        string jti,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        if (_shouldFail)
        {
            _shouldFail = false;
            throw new InvalidOperationException("Cache operation failed");
        }

        if (_nextJti != null && _nextJti != jti)
        {
            return false; // Unexpected JTI
        }

        return await Task.FromResult(_usedJtis.TryAdd(jti, expiresAt));
    }

    /// <summary>
    /// Cleans up expired JTI entries.
    /// </summary>
    public async Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var expiredJtis = _usedJtis
            .Where(kvp => kvp.Value <= now)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var jti in expiredJtis)
        {
            _usedJtis.TryRemove(jti, out _);
        }

        await Task.CompletedTask;
    }

    /// <summary>
    /// Clears all cached JTIs.
    /// </summary>
    public void Clear()
    {
        _usedJtis.Clear();
    }
}
