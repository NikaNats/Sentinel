namespace Sentinel.Application.Auth.Models;

public sealed record UserSessionInfo(
    string SessionId,
    string? IpAddress,
    DateTimeOffset? StartedAtUtc,
    DateTimeOffset? LastAccessUtc,
    IReadOnlyCollection<string> Clients);
