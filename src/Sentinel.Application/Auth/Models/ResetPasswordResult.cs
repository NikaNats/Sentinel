namespace Sentinel.Application.Auth.Models;

public sealed record ResetPasswordResult(bool IsSuccess, string Message, string? ErrorCode = null);
