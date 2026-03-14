namespace Sentinel.Application.Common.Abstractions;

public interface IJtiReplayCache
{
    ValueTask<bool> ExistsAsync(string jti, CancellationToken ct);
    Task StoreAsync(string jti, TimeSpan ttl, CancellationToken ct);
}

public sealed class ReplayCacheUnavailableException(string message, Exception innerException) : Exception(message, innerException);
