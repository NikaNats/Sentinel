namespace Sentinel.Security.Abstractions.Results;

/// <summary>
/// Centralized error codes and messages for security operations.
/// Replaces raw strings in SecurityResult.Failure() calls.
/// Enables consistent error handling across the NuGet suite.
/// </summary>
public static class SecurityErrors
{
    // Identity registry errors
    public const string IdentityConflict = "identity.conflict";
    public const string IdentityConflictMessage = "This user already exists in the identity provider.";

    public const string IdentityCreationFailed = "identity.creation_failed";
    public const string IdentityCreationFailedMessage = "Failed to create user in identity provider.";

    // Validation errors
    public const string ValidationFailed = "validation.failed";
    public const string TermsNotAccepted = "validation.terms_not_accepted";
    public const string TermsNotAcceptedMessage = "Terms must be accepted.";

    public const string InvalidEmail = "validation.invalid_email";
    public const string InvalidEmailMessage = "Invalid email format.";

    public const string InvalidUsername = "validation.invalid_username";
    public const string InvalidUsernameMessage = "Username does not meet requirements.";

    public const string WeakPassword = "validation.weak_password";
    public const string WeakPasswordMessage = "Password does not meet complexity requirements.";

    // Captcha errors
    public const string InvalidCaptcha = "captcha.invalid";
    public const string InvalidCaptchaMessage = "Invalid captcha verification.";

    // Token errors
    public const string TokenStoreFailed = "token.store_failed";
    public const string TokenStoreFailedMessage = "Failed to create verification token.";

    public const string TokenInvalid = "token.invalid";
    public const string TokenInvalidMessage = "Invalid or expired token.";

    public const string TokenExpired = "token.expired";
    public const string TokenExpiredMessage = "Token has expired.";

    // Email/notification errors
    public const string EmailDeliveryFailed = "email.delivery_failed";
    public const string EmailDeliveryFailedMessage = "Email delivery failed.";

    // DPoP errors
    public const string DpopProofInvalid = "dpop.proof_invalid";
    public const string DpopProofInvalidMessage = "DPoP proof validation failed.";

    public const string DpopNonceInvalid = "dpop.nonce_invalid";
    public const string DpopNonceInvalidMessage = "DPoP nonce is invalid or expired.";

    public const string DpopSignatureInvalid = "dpop.signature_invalid";
    public const string DpopSignatureInvalidMessage = "DPoP proof signature verification failed.";

    // Session errors
    public const string SessionExpired = "session.expired";
    public const string SessionExpiredMessage = "Session has expired.";

    public const string SessionInvalid = "session.invalid";
    public const string SessionInvalidMessage = "Session is invalid or blacklisted.";

    // Generic errors
    public const string Unauthorized = "security.unauthorized";
    public const string UnauthorizedMessage = "Operation is not authorized.";

    public const string Forbidden = "security.forbidden";
    public const string ForbiddenMessage = "Operation is forbidden.";

    public const string InternalError = "security.internal_error";
    public const string InternalErrorMessage = "An internal security error occurred.";
}
