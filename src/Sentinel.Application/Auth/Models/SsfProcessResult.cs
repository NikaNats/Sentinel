namespace Sentinel.Application.Auth.Models;

public sealed record SsfProcessResult(bool IsSuccess, bool IsUnauthorized, string? Error)
{
    public static SsfProcessResult Success() => new(true, false, null);

    public static SsfProcessResult Unauthorized(string error) => new(false, true, error);

    public static SsfProcessResult Invalid(string error) => new(false, false, error);
}
