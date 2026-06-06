namespace Sentinel.Security.Abstractions.Idempotency;

public sealed record CachedHttpResponse(int StatusCode, string ContentType, byte[] Body);

public interface IIdempotencyStore
{
    Task<(IdempotencyAcquireResult State, CachedHttpResponse? Response)> TryAcquireAsync(
        string key,
        TimeSpan inProgressTtl,
        CancellationToken cancellationToken = default);

    Task MarkCompletedAsync(
        string key,
        CachedHttpResponse response,
        TimeSpan completedTtl,
        CancellationToken cancellationToken = default);

    Task ReleaseAsync(string key, CancellationToken cancellationToken = default);
}
