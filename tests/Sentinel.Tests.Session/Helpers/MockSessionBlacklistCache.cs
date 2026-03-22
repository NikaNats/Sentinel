namespace Sentinel.Tests.Session;

/// <summary>
/// Mock implementation of ISessionBlacklistCache for unit testing.
/// Tracks blacklisted sessions in memory with simple expiration tracking.
/// </summary>
public sealed class MockSessionBlacklistCache : ISessionBlacklistCache
{
    private readonly Dictionary<string, DateTimeOffset> _blacklist = new();

    /// <summary>
    /// Gets all currently blacklisted session IDs.
    /// </summary>
    public IReadOnlyCollection<string> BlacklistedSessions => _blacklist.Keys;

    public Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _blacklist[sessionId] = expiresAt;
        return Task.CompletedTask;
    }

    public Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var isBlacklisted = _blacklist.ContainsKey(sessionId);
        return Task.FromResult(isBlacklisted);
    }

    public Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var now = DateTimeOffset.UtcNow;
        var expired = _blacklist
            .Where(kvp => kvp.Value <= now)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var sessionId in expired)
        {
            _blacklist.Remove(sessionId);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Removes expired entries with a specific reference time (for testing cleanup scenarios).
    /// </summary>
    public void CleanupExpiredAt(DateTimeOffset referenceTime)
    {
        var expired = _blacklist
            .Where(kvp => kvp.Value <= referenceTime)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var sessionId in expired)
        {
            _blacklist.Remove(sessionId);
        }
    }
}
