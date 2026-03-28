using System.Collections.Concurrent;

namespace Sentinel.Tests.Session.Helpers;

/// <summary>
///     High-assurance mock for ISessionBlacklistCache with concurrency safety and failure injection.
///     ARCHITECTURE: Uses ConcurrentDictionary to support parallel test execution without race conditions.
///     Enables deterministic failure injection via ExceptionToThrow for Fail-Closed testing.
///     This mock is NOT a simple spy - it's an adversarial test harness that simulates infrastructure failures.
///     When ExceptionToThrow is set, ALL operations (BlacklistSessionAsync, IsBlacklistedAsync) will throw,
///     forcing the SessionManager to verify its Fail-Closed behavior.
/// </summary>
public sealed class MockSessionBlacklistCache : ISessionBlacklistCache
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _blacklist = new();

    /// <summary>
    ///     If set, the next cache operation will throw this exception.
    ///     Used to verify Fail-Closed logic in SessionManager when cache is unavailable.
    ///     This simulates real infrastructure failures: Redis connection lost, network timeout, permission denied, etc.
    /// </summary>
    public Exception? ExceptionToThrow { get; set; }

    /// <summary>
    ///     Gets all currently blacklisted session IDs (thread-safe snapshot).
    /// </summary>
    public IReadOnlyCollection<string> BlacklistedSessions => _blacklist.Keys.ToList();

    public Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // ✅ FAILURE INJECTION: Simulate infrastructure unavailability
        if (ExceptionToThrow is not null)
        {
            throw ExceptionToThrow;
        }

        _blacklist[sessionId] = expiresAt;
        return Task.CompletedTask;
    }

    public Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // ✅ FAILURE INJECTION: Simulate infrastructure unavailability
        if (ExceptionToThrow is not null)
        {
            throw ExceptionToThrow;
        }

        var isBlacklisted = _blacklist.ContainsKey(sessionId);
        return Task.FromResult(isBlacklisted);
    }

    public Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // ✅ FAILURE INJECTION: Simulate infrastructure unavailability
        if (ExceptionToThrow is not null)
        {
            throw ExceptionToThrow;
        }

        var now = DateTimeOffset.UtcNow;
        var kvpList = _blacklist.ToList();
        var expired = kvpList
            .Where(kvp => kvp.Value <= now)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var sessionId in expired)
        {
            _blacklist.TryRemove(sessionId, out _);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    ///     Removes expired entries with a specific reference time (for testing cleanup scenarios).
    ///     Thread-safe implementation to support parallel test runners.
    /// </summary>
    public void CleanupExpiredAt(DateTimeOffset referenceTime)
    {
        var kvpList = _blacklist.ToList();
        var expired = kvpList
            .Where(kvp => kvp.Value <= referenceTime)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var sessionId in expired)
        {
            _blacklist.TryRemove(sessionId, out _);
        }
    }
}
