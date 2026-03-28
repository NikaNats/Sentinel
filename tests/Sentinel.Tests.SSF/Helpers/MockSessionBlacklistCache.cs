namespace Sentinel.Tests.SSF.Helpers;

/// <summary>
///     Mock ISessionBlacklistCache for testing.
/// </summary>
public sealed class MockSessionBlacklistCache : ISessionBlacklistCache
{
    private readonly Dictionary<string, DateTimeOffset> _blacklist = [];

    public Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        _blacklist[sessionId] = expiresAt;
        return Task.CompletedTask;
    }

    public Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        var isBlacklisted = _blacklist.TryGetValue(sessionId, out var expiresAt) && expiresAt > DateTimeOffset.UtcNow;
        return Task.FromResult(isBlacklisted);
    }

    public Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var expired = _blacklist.Where(kvp => kvp.Value <= now).Select(kvp => kvp.Key).ToList();
        foreach (var sessionId in expired)
        {
            _blacklist.Remove(sessionId);
        }

        return Task.CompletedTask;
    }

    public static MockSessionBlacklistCache Create() => new();
}
