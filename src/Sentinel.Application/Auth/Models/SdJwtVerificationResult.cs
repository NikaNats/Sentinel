using System.Security.Claims;

namespace Sentinel.Application.Auth.Models;

public sealed record SdJwtVerificationResult(bool IsSuccess, ClaimsPrincipal? Principal, string? Error)
{
    public static SdJwtVerificationResult Success(ClaimsPrincipal principal) => new(true, principal, null);

    public static SdJwtVerificationResult Fail(string error) => new(false, null, error);
}
