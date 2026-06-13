using Sentinel.Application.Auth.Options;
using Sentinel.Infrastructure.Auth;

namespace Sentinel.Tests.Unit.Auth;

public sealed class PasswordStrengthValidatorTests
{
    private readonly EnterprisePasswordStrengthValidator _validator;

    public PasswordStrengthValidatorTests()
    {
        var options = Microsoft.Extensions.Options.Options.Create(new PasswordPolicyOptions
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

    [Fact(DisplayName = "✅ Strong password passes validation successfully")]
    public void Validate_StrongPassword_ReturnsSuccess()
    {
        var result = _validator.Validate("Secure$Pass9513");
        Assert.True(result.IsValid);
        Assert.Null(result.Error);
    }

    [Theory(DisplayName = "❌ Weak passwords are rejected with appropriate error messages")]
    [InlineData("short1$", "Password length must be at least 12 characters.")]
    [InlineData("nouppercas&1", "Password must contain at least one uppercase letter (A-Z).")]
    [InlineData("NOLOWERCASE&1", "Password must contain at least one lowercase letter (a-z).")]
    [InlineData("NoSpecialChar12", "Password must contain at least one special character (!@#$%^&*).")]
    [InlineData("NoDigitsPresent$", "Password must contain at least one digit (0-9).")]
    public void Validate_WeakPasswords_ReturnsExpectedFailures(string password, string expectedError)
    {
        var result = _validator.Validate(password);
        Assert.False(result.IsValid);
        Assert.Equal(expectedError, result.Error);
    }

    [Fact(DisplayName = "🛡️ Common passwords (Blacklist) are blocked immediately")]
    public void Validate_BlacklistedPassword_ReturnsFailure()
    {
        var result = _validator.Validate("password12345");
        Assert.False(result.IsValid);
        Assert.Contains("too common or easily guessable", result.Error);
    }
}
