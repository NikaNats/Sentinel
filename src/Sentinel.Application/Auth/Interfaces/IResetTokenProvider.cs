namespace Sentinel.Application.Auth.Interfaces;

using Sentinel.Domain.Auth;

/// <summary>
/// Service contract for password reset token generation and validation.
/// Belongs in Application Layer: requires external infrastructure (entropy, storage, TTL).
/// This MUST NOT be implemented in the Domain.
/// </summary>
public interface IResetTokenProvider
{
    /// <summary>
    /// Generates an opaque ResetToken for the specified email.
    /// The association between token.TokenHandle and email is persisted server-side
    /// with a short TTL (typically 15-30 minutes).
    /// </summary>
    /// <param name="email">User email address (will be hashed/stored server-side).</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>ResetToken with opaque handle (safe to send via email/SMS).</returns>
    Task<ResetToken> GenerateTokenAsync(string email, CancellationToken ct);

    /// <summary>
    /// Validates the opaque handle and returns the associated email if valid.
    /// Implementation MUST enforce single-use semantics (consume on validation).
    /// Expired or already-consumed tokens must return (IsValid: false, Email: null).
    /// </summary>
    /// <param name="tokenHandle">Opaque token handle from user input.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>
    /// Tuple: (IsValid, Email). IsValid=true only if token is valid, unexpired, and unconsumed.
    /// Email is returned only if IsValid=true (prevents email leakage on invalid tokens).
    /// </returns>
    Task<(bool IsValid, string? Email)> ValidateAndConsumeAsync(string tokenHandle, CancellationToken ct);
}
