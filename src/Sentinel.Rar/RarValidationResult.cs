namespace Sentinel.RAR;

/// <summary>
/// Result of validating a payload against RAR authorization details.
/// </summary>
public sealed record RarValidationResult(
    bool IsValid,
    AuthorizationDetail? MatchedDetail,
    string? Error)
{
    /// <summary>
    /// Creates a successful validation result with the matched authorization detail.
    /// </summary>
    /// <param name="detail">The authorization detail that matched the payload.</param>
    /// <returns>A successful validation result.</returns>
    public static RarValidationResult Success(AuthorizationDetail detail) =>
        new(true, detail, null);

    /// <summary>
    /// Creates a failed validation result with an error message.
    /// </summary>
    /// <param name="error">Description of the validation failure.</param>
    /// <returns>A failed validation result.</returns>
    public static RarValidationResult Failure(string error) =>
        new(false, null, error);
}

/// <summary>
/// Result of extracting and parsing RAR authorization details from a claims principal.
/// </summary>
public sealed record RarExtractionResult(
    bool IsValid,
    AuthorizationDetail[]? Details,
    string? Error)
{
    /// <summary>
    /// Creates a successful extraction result with the parsed authorization details.
    /// </summary>
    /// <param name="details">The parsed authorization details.</param>
    /// <returns>A successful extraction result.</returns>
    public static RarExtractionResult Success(AuthorizationDetail[] details) =>
        new(true, details, null);

    /// <summary>
    /// Creates a failed extraction result with an error message.
    /// </summary>
    /// <param name="error">Description of the extraction failure.</param>
    /// <returns>A failed extraction result.</returns>
    public static RarExtractionResult Failure(string error) =>
        new(false, null, error);
}
