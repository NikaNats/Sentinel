using System.Text.RegularExpressions;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;

namespace Sentinel.Application.Auth;

public sealed class PasswordStrengthValidator : IPasswordStrengthValidator
{
    private static readonly Regex UppercaseRegex = new("[A-Z]", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex LowercaseRegex = new("[a-z]", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex DigitRegex = new("[0-9]", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex SpecialRegex = new("[^a-zA-Z0-9]", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly HashSet<string> CommonPasswords =
    [
        "password",
        "password123",
        "qwerty",
        "qwerty123",
        "12345678",
        "123456789",
        "letmein",
        "admin",
        "welcome123"
    ];

    public PasswordStrengthValidationResult Validate(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return new PasswordStrengthValidationResult(false, "weak_password", "Password is required.");
        }

        if (password.Length < 12)
        {
            return new PasswordStrengthValidationResult(false, "weak_password", "Password must be at least 12 characters.");
        }

        if (!UppercaseRegex.IsMatch(password))
        {
            return new PasswordStrengthValidationResult(false, "weak_password", "Password must contain an uppercase letter.");
        }

        if (!LowercaseRegex.IsMatch(password))
        {
            return new PasswordStrengthValidationResult(false, "weak_password", "Password must contain a lowercase letter.");
        }

        if (!DigitRegex.IsMatch(password))
        {
            return new PasswordStrengthValidationResult(false, "weak_password", "Password must contain a digit.");
        }

        if (!SpecialRegex.IsMatch(password))
        {
            return new PasswordStrengthValidationResult(false, "weak_password", "Password must contain a special character.");
        }

        if (CommonPasswords.Contains(password.Trim().ToLowerInvariant()))
        {
            return new PasswordStrengthValidationResult(false, "weak_password", "Password is too common.");
        }

        return new PasswordStrengthValidationResult(true);
    }
}
