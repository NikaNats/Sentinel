namespace Sentinel.Application.Auth.Models;

public sealed record ResetPasswordRequest(string Token, string NewPassword);
