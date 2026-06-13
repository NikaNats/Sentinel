using FsCheck;
using FsCheck.Fluent;
using Microsoft.Extensions.Options;
using Sentinel.Application.Auth.Options;
using Sentinel.Infrastructure.Auth;

namespace Sentinel.Tests.Security.Security;

public sealed class PasswordStrengthPropertyTests
{
    private readonly EnterprisePasswordStrengthValidator _validator;

    public PasswordStrengthPropertyTests()
    {
        var options = Options.Create(new PasswordPolicyOptions
        {
            MinimumLength = 12,
            RequireDigit = true,
            RequireUppercase = true,
            RequireLowercase = true,
            RequireNonAlphanumeric = true,
            MinimumEntropyBits = 50.0
        });

        _validator = new EnterprisePasswordStrengthValidator(options);
    }

    [Fact(DisplayName = "🛡️ Invariant 1: Any password shorter than 12 characters is always rejected")]
    public void Verify_PasswordsShorterThan12_AreAlwaysRejected()
    {
        var property = Prop.ForAll<string>(password =>
        {
            if (password == null || password.Length < 12)
            {
                var result = _validator.Validate(password ?? string.Empty);
                return !result.IsValid;
            }

            return true;
        });

        Check.QuickThrowOnFailure(property);
    }

    [Fact(DisplayName = "🛡️ Invariant 2: Any password without digits is always rejected")]
    public void Verify_PasswordsWithoutDigits_AreAlwaysRejected()
    {
        var property = Prop.ForAll<string>(password =>
        {
            if (password is { Length: >= 12 } && !password.Any(char.IsDigit))
            {
                var result = _validator.Validate(password);
                return !result.IsValid;
            }

            return true;
        });

        Check.QuickThrowOnFailure(property);
    }

    [Fact(DisplayName = "🛡️ Invariant 3: Any password without uppercase letters is always rejected")]
    public void Verify_PasswordsWithoutUppercase_AreAlwaysRejected()
    {
        var property = Prop.ForAll<string>(password =>
        {
            if (password is { Length: >= 12 } && !password.Any(char.IsUpper))
            {
                var result = _validator.Validate(password);
                return !result.IsValid;
            }

            return true;
        });

        Check.QuickThrowOnFailure(property);
    }

    [Fact(DisplayName = "🛡️ Invariant 4: Any password without special characters is always rejected")]
    public void Verify_PasswordsWithoutSpecialCharacters_AreAlwaysRejected()
    {
        var property = Prop.ForAll<string>(password =>
        {
            if (password is { Length: >= 12 } && password.All(char.IsLetterOrDigit))
            {
                var result = _validator.Validate(password);
                return !result.IsValid;
            }

            return true;
        });

        Check.QuickThrowOnFailure(property);
    }
}
