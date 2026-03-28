namespace Sentinel.Redis;

/// <summary>
///     Provides asynchronous, lazy-initialized access to a Redis connection multiplexer.
///     This abstraction decouples connection initialization from application startup,
///     enabling graceful Kubernetes pod startup and zero-downtime deployments.
///     The connection is established on first demand via GetConnectionAsync, not during
///     DI container construction, preventing CrashLoopBackOff if Redis is not yet ready.
/// </summary>
public interface IRedisConnectionProvider : IAsyncDisposable
{
    /// <summary>
    ///     Asynchronously retrieves the connection multiplexer.
    ///     On first call, establishes the connection with background reconnection logic enabled.
    ///     On subsequent calls, returns the cached instance.
    ///     Thread-safe via internal SemaphoreSlim to prevent thundering herd during startup.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for the async operation.</param>
    /// <returns>An initialized IConnectionMultiplexer instance.</returns>
    ValueTask<IConnectionMultiplexer> GetConnectionAsync(CancellationToken cancellationToken = default);
}
