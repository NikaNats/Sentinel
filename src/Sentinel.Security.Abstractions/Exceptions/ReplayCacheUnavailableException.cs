namespace Sentinel.Security.Abstractions.Exceptions;

/// <summary>
///     Thrown when the JTI replay cache or DPoP proof replay cache is unreachable.
///     The calling middleware MUST return HTTP 503 — requests must not be permitted
///     through without replay protection.
/// </summary>
public sealed class ReplayCacheUnavailableException : SecurityInfrastructureException
{
    /// <summary>
    ///     Initializes a new instance of the <see cref="ReplayCacheUnavailableException" /> class.
    /// </summary>
    public ReplayCacheUnavailableException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
