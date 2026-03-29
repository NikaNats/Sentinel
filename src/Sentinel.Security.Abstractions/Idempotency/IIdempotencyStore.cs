namespace Sentinel.Security.Abstractions.Idempotency;

/// <summary>
///     Backend store for request idempotency state.
/// </summary>
public interface IIdempotencyStore
{
    /// <summary>
    ///     Attempts to acquire execution for a key with an in-progress TTL.
    /// </summary>
    /// <param name="key">Fully-qualified idempotency key.</param>
    /// <param name="inProgressTtl">TTL for in-progress execution lock.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    ///     <see cref="IdempotencyAcquireResult.Acquired" /> when lock is acquired,
    ///     <see cref="IdempotencyAcquireResult.Completed" /> when request was already completed,
    ///     <see cref="IdempotencyAcquireResult.InProgress" /> when another request is still running.
    /// </returns>
    Task<IdempotencyAcquireResult> TryAcquireAsync(
        string key,
        TimeSpan inProgressTtl,
        CancellationToken cancellationToken = default);

    /// <summary>
    ///     Marks a key as completed with the configured completion TTL.
    /// </summary>
    /// <param name="key">Fully-qualified idempotency key.</param>
    /// <param name="completedTtl">TTL for completed request record.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task MarkCompletedAsync(string key, TimeSpan completedTtl, CancellationToken cancellationToken = default);

    /// <summary>
    ///     Removes a key from the idempotency backend.
    /// </summary>
    /// <param name="key">Fully-qualified idempotency key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task ReleaseAsync(string key, CancellationToken cancellationToken = default);
}
