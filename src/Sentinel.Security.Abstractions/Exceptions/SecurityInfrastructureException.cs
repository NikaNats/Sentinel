namespace Sentinel.Security.Abstractions.Exceptions;

/// <summary>
///     Base exception for fail-closed security infrastructure failures.
///     Callers MUST treat this as a transient 503 — never bypass security checks
///     when this exception is caught.
/// </summary>
public abstract class SecurityInfrastructureException : Exception
{
    /// <summary>
    ///     Initializes a new instance of the <see cref="SecurityInfrastructureException" /> class.
    /// </summary>
    protected SecurityInfrastructureException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
