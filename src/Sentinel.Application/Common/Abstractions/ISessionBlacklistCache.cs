namespace Sentinel.Application.Common.Abstractions;

public interface ISessionBlacklistCache
{
    Task BlacklistSessionAsync(string sessionId, TimeSpan ttl, CancellationToken ct);
    ValueTask<bool> IsSessionBlacklistedAsync(string sessionId, CancellationToken ct);
}
