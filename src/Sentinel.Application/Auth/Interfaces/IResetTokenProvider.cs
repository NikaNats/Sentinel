namespace Sentinel.Application.Auth.Interfaces;

using Sentinel.Domain.Auth;
using Sentinel.Application.Auth.Models;

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
    /// Validates the opaque handle and returns a discriminated result.
    /// Implementation MUST enforce single-use semantics (consume on validation).
    /// Provides type-safe, extensible failure reasons instead of fragile tuples.
    /// </summary>
    /// <param name="tokenHandle">Opaque token handle from user input.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>
    /// Discriminated TokenValidationResult:
    /// - Success(email): Token valid, unexpired, unconsumed
    /// - Expired: Token past ExpiresAtUtc
    /// - AlreadyConsumed: Single-use token already used
    /// - NotFound: Handle not found or tampered
    /// - ValidationFailed: Storage/processing error
    /// </returns>
    Task<TokenValidationResult> ValidateAndConsumeAsync(string tokenHandle, CancellationToken ct);
}
