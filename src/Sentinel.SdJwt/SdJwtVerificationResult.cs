namespace Sentinel.SdJwt;

/// <summary>
/// Result of SD-JWT presentation verification.
/// </summary>
public sealed record SdJwtVerificationResult(
    bool IsValid,
    ClaimsPrincipal? Principal,
    string? Error)
{
    /// <summary>
    /// Creates a successful verification result with the verified principal.
    /// </summary>
    /// <param name="principal">The ClaimsPrincipal with reconstructed claims from disclosed values.</param>
    /// <returns>A successful verification result.</returns>
    public static SdJwtVerificationResult Success(ClaimsPrincipal principal) =>
        new(true, principal, null);

    /// <summary>
    /// Creates a failed verification result with an error message.
    /// </summary>
    /// <param name="error">Description of the verification failure.</param>
    /// <returns>A failed verification result.</returns>
    public static SdJwtVerificationResult Failure(string error) =>
        new(false, null, error);
}

/// <summary>
/// Result of validating an SD-JWT issuer token (before disclosure processing).
/// </summary>
public sealed record SdJwtIssuerTokenValidationResult(
    bool IsValid,
    JsonWebToken? Token,
    string? Error)
{
    /// <summary>
    /// Creates a successful token validation result.
    /// </summary>
    /// <param name="token">The validated JWT token.</param>
    /// <returns>A successful validation result.</returns>
    public static SdJwtIssuerTokenValidationResult Success(JsonWebToken token) =>
        new(true, token, null);

    /// <summary>
    /// Creates a failed validation result.
    /// </summary>
    /// <param name="error">Description of the validation failure.</param>
    /// <returns>A failed validation result.</returns>
    public static SdJwtIssuerTokenValidationResult Failure(string error) =>
        new(false, null, error);
}
