namespace Sentinel.Application.Auth.Models;

public sealed record ForgotPasswordRequest(string Email, string CaptchaToken);
