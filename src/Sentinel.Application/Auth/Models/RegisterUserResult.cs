namespace Sentinel.Application.Auth.Models;

public sealed record RegisterUserResult(bool IsSuccess, string Message, string? ErrorCode = null);
