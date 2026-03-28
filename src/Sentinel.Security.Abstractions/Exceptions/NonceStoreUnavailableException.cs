namespace Sentinel.Security.Abstractions.Exceptions;

/// <summary>
///     Thrown when the DPoP nonce store is unreachable.
/// </summary>
public sealed class NonceStoreUnavailableException : SecurityInfrastructureException
{
    /// <summary>
    ///     Initializes a new instance of the <see cref="NonceStoreUnavailableException" /> class.
    /// </summary>
    public NonceStoreUnavailableException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
