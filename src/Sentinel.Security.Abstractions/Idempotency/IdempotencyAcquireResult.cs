namespace Sentinel.Security.Abstractions.Idempotency;

/// <summary>
///     The outcome of attempting to acquire an idempotency key lock.
/// </summary>
public enum IdempotencyAcquireResult
{
    /// <summary>
    ///     The lock was acquired and request execution can proceed.
    /// </summary>
    Acquired = 0,

    /// <summary>
    ///     A previous request already completed for this key.
    /// </summary>
    Completed = 1,

    /// <summary>
    ///     Another request is currently executing for this key.
    /// </summary>
    InProgress = 2
}
