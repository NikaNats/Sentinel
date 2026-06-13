// Sentinel Security API - FAPI 2.0 Compliant

using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.Auth.Options;

namespace Sentinel.Infrastructure.Auth;

internal sealed class EnterprisePasswordStrengthValidator : IPasswordStrengthValidator
{
    private static readonly string[] DefaultCommonPasswords =
    [
        "123456", "password", "123456789", "qwerty", "12345678", "111111",
        "1234567", "letmein123", "password123", "admin123", "welcome123"
    ];

    private readonly HashSet<string> _blacklist;
    private readonly PasswordPolicyOptions _options;

    public EnterprisePasswordStrengthValidator(IOptions<PasswordPolicyOptions> options)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _blacklist = new HashSet<string>(DefaultCommonPasswords, StringComparer.OrdinalIgnoreCase);

        foreach (var word in _options.CustomBlacklist)
        {
            _blacklist.Add(word);
        }
    }

    public PasswordStrengthValidationResult Validate(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return PasswordStrengthValidationResult.Failure("Password cannot be empty.");
        }

        if (password.Length < _options.MinimumLength)
        {
            return PasswordStrengthValidationResult.Failure(
                $"Password length must be at least {_options.MinimumLength} characters.");
        }

        if (password.Length > _options.MaximumLength)
        {
            return PasswordStrengthValidationResult.Failure(
                $"Password length cannot exceed {_options.MaximumLength} characters.");
        }

        // Protection against dictionary attacks
        if (_blacklist.Contains(password) || IsSequentialPattern(password))
        {
            return PasswordStrengthValidationResult.Failure(
                "This password is too common or easily guessable. Please choose another one.");
        }

        // Character class validation
        if (_options.RequireUppercase && !password.Any(char.IsUpper))
        {
            return PasswordStrengthValidationResult.Failure(
                "Password must contain at least one uppercase letter (A-Z).");
        }

        if (_options.RequireLowercase && !password.Any(char.IsLower))
        {
            return PasswordStrengthValidationResult.Failure(
                "Password must contain at least one lowercase letter (a-z).");
        }

        if (_options.RequireDigit && !password.Any(char.IsDigit))
        {
            return PasswordStrengthValidationResult.Failure("Password must contain at least one digit (0-9).");
        }

        if (_options.RequireNonAlphanumeric && !password.Any(c => !char.IsLetterOrDigit(c)))
        {
            return PasswordStrengthValidationResult.Failure(
                "Password must contain at least one special character (!@#$%^&*).");
        }

        var entropy = CalculatePoolEntropy(password);
        if (entropy < _options.MinimumEntropyBits)
        {
            return PasswordStrengthValidationResult.Failure(
                "Password cryptographic complexity is too low. Use a more diverse combination of characters.");
        }

        return PasswordStrengthValidationResult.Success();
    }

    private static double CalculatePoolEntropy(string password)
    {
        var poolSize = 0;
        if (password.Any(char.IsLower))
        {
            poolSize += 26;
        }

        if (password.Any(char.IsUpper))
        {
            poolSize += 26;
        }

        if (password.Any(char.IsDigit))
        {
            poolSize += 10;
        }

        if (password.Any(c => !char.IsLetterOrDigit(c)))
        {
            poolSize += 33;
        }

        if (poolSize == 0)
        {
            return 0;
        }

        return password.Length * Math.Log2(poolSize);
    }

    private static bool IsSequentialPattern(string password)
    {
        if (password.Length < 4)
        {
            return false;
        }

        for (var i = 0; i < password.Length - 3; i++)
        {
            if (password[i + 1] == password[i] + 1 &&
                password[i + 2] == password[i] + 2 &&
                password[i + 3] == password[i] + 3)
            {
                return true;
            }
        }

        return false;
    }
}
