namespace Sentinel.Security.Abstractions.SSF;

/// <summary>
/// Processes Server-Sent Events (SSF / SET) tokens for real-time security notifications.
/// </summary>
public interface ISsfEventProcessor
{
    /// <summary>
    /// Processes a Server-Sent Event token (RFC 8936 / CAEP spec).
    /// </summary>
    /// <param name="setToken">The SET JWT token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Success if processed, failure with explanation otherwise.</returns>
    Task<Results.SecurityResult> ProcessAsync(
        string setToken,
        CancellationToken cancellationToken = default);
}
