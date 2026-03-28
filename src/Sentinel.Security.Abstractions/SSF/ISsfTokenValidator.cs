namespace Sentinel.Security.Abstractions.SSF;

/// <summary>
///     Validates Server-Sent Event tokens (RFC 8936 / CAEP).
///     Responsible for signature verification, issuer validation, and structural validation.
/// </summary>
public interface ISsfTokenValidator
{
    /// <summary>
    ///     Validates a SET token asynchronously.
    /// </summary>
    /// <param name="setToken">The JWT token to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Validation result containing the parsed token or error details.</returns>
    Task<SsfValidationResult> ValidateAsync(string setToken, CancellationToken cancellationToken = default);
}

/// <summary>
///     Result of SSF token validation.
/// </summary>
/// <param name="IsValid">Whether the token passed validation.</param>
/// <param name="Token">The parsed token (populated only if IsValid is true).</param>
/// <param name="Error">Error message if validation failed.</param>
public sealed record SsfValidationResult(bool IsValid, SsfEventToken? Token, string? Error)
{
    /// <summary>
    ///     Creates a successful validation result.
    /// </summary>
    public static SsfValidationResult Success(SsfEventToken token) => new(true, token, null);

    /// <summary>
    ///     Creates a failed validation result.
    /// </summary>
    public static SsfValidationResult Fail(string error) => new(false, null, error);
}
