using Sentinel.Application.Auth.Models;

namespace Sentinel.Application.Auth.Interfaces;

public interface IPasswordStrengthValidator
{
    PasswordStrengthValidationResult Validate(string password);
}
