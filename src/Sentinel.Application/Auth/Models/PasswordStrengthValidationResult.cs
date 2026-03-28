namespace Sentinel.Application.Auth.Models;

/// <summary>
///     Result of password strength validation.
/// </summary>
public sealed record PasswordStrengthValidationResult(
    bool IsValid,
    string? Error)
{
    /// <summary>
    ///     Creates a successful validation result.
    /// </summary>
    /// <returns>A successful validation result.</returns>
    public static PasswordStrengthValidationResult Success() =>
        new(true, null);

    /// <summary>
    ///     Creates a failed validation result with an error message.
    /// </summary>
    /// <param name="error">Description of the validation failure.</param>
    /// <returns>A failed validation result.</returns>
    public static PasswordStrengthValidationResult Failure(string error) =>
        new(false, error);
}
