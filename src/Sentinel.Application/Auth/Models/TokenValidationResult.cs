namespace Sentinel.Application.Auth.Models;

/// <summary>
///     Discriminated result for password reset token validation.
///     Replaces fragile (bool, string?) tuple with type-safe outcome modeling.
///     Enables safe pattern matching and extensible failure reasons.
/// </summary>
public abstract record TokenValidationResult
{
    /// <summary>
    ///     Pattern matching helper for success case.
    ///     Usage: if (result is TokenValidationResult.Success success) { ... }
    /// </summary>
    public string? Email => this switch
    {
        Success s => s.Email,
        _ => null
    };

    /// <summary>
    ///     Token is valid, unexpired, unconsumed, and associated with an email.
    ///     Safe to proceed with password reset flow.
    /// </summary>
    public sealed record Success : TokenValidationResult
    {
        public new required string Email { get; init; }
    }

    /// <summary>
    ///     Token has expired (DateTimeOffset.UtcNow > ExpiresAtUtc).
    ///     Caller should prompt user to request new reset token.
    /// </summary>
    public sealed record Expired : TokenValidationResult;

    /// <summary>
    ///     Token was already consumed (single-use semantics enforced).
    ///     Indicates potential replay attack or user clicking link twice.
    /// </summary>
    public sealed record AlreadyConsumed : TokenValidationResult;

    /// <summary>
    ///     Token handle not found in store or invalid format.
    ///     Indicates tampering, invalid input, or timing attack.
    /// </summary>
    public sealed record NotFound : TokenValidationResult;

    /// <summary>
    ///     Token validation failed for other reasons (storage error, etc.).
    /// </summary>
    public sealed record ValidationFailed(string Reason) : TokenValidationResult;
}
