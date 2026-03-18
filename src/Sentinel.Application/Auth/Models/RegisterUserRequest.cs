namespace Sentinel.Application.Auth.Models;

public sealed record RegisterUserRequest(
    string Email,
    string Username,
    string Password,
    string CaptchaToken,
    bool AcceptTerms);
