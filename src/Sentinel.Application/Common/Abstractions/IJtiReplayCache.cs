namespace Sentinel.Application.Common.Abstractions;

public interface IJtiReplayCache
{
    Task<bool> TryStoreIfNotExistsAsync(string jti, TimeSpan ttl, CancellationToken ct);
}

public sealed class ReplayCacheUnavailableException(string message, Exception innerException) : Exception(message, innerException);
