namespace Sentinel.SampleHost.Models;

public sealed record DocumentDto(
    Guid Id,
    string OwnerSub,
    string Title,
    string Content,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);
