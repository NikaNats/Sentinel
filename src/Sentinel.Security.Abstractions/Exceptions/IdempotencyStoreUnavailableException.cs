namespace Sentinel.Security.Abstractions.Exceptions;

/// <summary>
///     Thrown when the idempotency state store is unavailable.
///     Calling code should fail closed and return HTTP 503.
/// </summary>
public sealed class IdempotencyStoreUnavailableException : SecurityInfrastructureException
{
    /// <summary>
    ///     Initializes a new instance of the <see cref="IdempotencyStoreUnavailableException" /> class.
    /// </summary>
    public IdempotencyStoreUnavailableException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
