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
    public const string InvalidRequest = "/errors/invalid-request";
    public const string InvalidCaptcha = "/errors/invalid-captcha";
    public const string TermsNotAccepted = "/errors/terms-not-accepted";
    public const string InvalidOrExpiredToken = "/errors/invalid-or-expired-token";
    public const string TokenAlreadyConsumed = "/errors/token-already-consumed";
    public const string VerificationTokenStoreFailed = "/errors/verification-token-store-failed";
    public const string MissingAuthorizationDetail = "/errors/missing-authorization-detail";
    public const string AuthorizationBoundsExceeded = "/errors/authorization-bounds-exceeded";
}
