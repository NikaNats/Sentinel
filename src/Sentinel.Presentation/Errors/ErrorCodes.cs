namespace Sentinel.Errors;

public static class ErrorCodes
{
    public const string InternalServerError = "/errors/internal-server-error";
    public const string Unauthorized = "/errors/unauthorized";
    public const string TokenTheftDetected = "/errors/token-theft-detected";
    public const string MissingDpopProof = "/errors/missing-dpop-proof";
    public const string InvalidDpopProof = "/errors/invalid-dpop-proof";
    public const string InsufficientAcr = "/errors/insufficient-acr";
    public const string MissingScope = "/errors/missing-scope";
    public const string MissingIdempotencyKey = "/errors/missing-idempotency-key";
    public const string IdempotencyConflict = "/errors/idempotency-conflict";
    public const string IdempotencyUnavailable = "/errors/idempotency-unavailable";
    public const string InvalidCurrentPassword = "/errors/invalid-current-password";
    public const string WeakPassword = "/errors/weak-password";
    public const string MfaNotConfigured = "/errors/mfa-not-configured";
}
