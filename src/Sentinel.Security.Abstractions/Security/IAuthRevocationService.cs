namespace Sentinel.Security.Abstractions.Security;

/// <summary>
/// Revokes authentication and authorization for a user across all sessions and devices.
/// Used for logout, account lockout, and security event response (CAE/CAEP).
/// </summary>
public interface IAuthRevocationService
{
    /// <summary>
    /// Revokes all sessions and authentication tokens for a specific subject.
    /// </summary>
    /// <remarks>
    /// This operation is typically invoked:
    /// - When receiving a CAE/CAEP event (security event token) indicating user status change
    /// - During account lockout or password change
    /// - When credential compromise is detected
    ///
    /// All active sessions, access tokens, and refresh tokens for the subject should be invalidated.
    /// </remarks>
    /// <param name="subject">The user identifier (typically 'sub' claim).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Task representing the async operation.</returns>
    Task RevokeAllSessionsAsync(string subject, CancellationToken cancellationToken = default);
}
