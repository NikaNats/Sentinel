namespace Sentinel.Application.Auth.Models;

public sealed record PasswordStrengthValidationResult(bool IsValid, string? ErrorCode = null, string? Message = null);
