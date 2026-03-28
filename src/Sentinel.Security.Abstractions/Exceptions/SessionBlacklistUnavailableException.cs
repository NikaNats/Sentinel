namespace Sentinel.Security.Abstractions.Exceptions;

/// <summary>
///     Thrown when the session blacklist cache is unreachable.
/// </summary>
public sealed class SessionBlacklistUnavailableException : SecurityInfrastructureException
{
    /// <summary>
    ///     Initializes a new instance of the <see cref="SessionBlacklistUnavailableException" /> class.
    /// </summary>
    public SessionBlacklistUnavailableException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
