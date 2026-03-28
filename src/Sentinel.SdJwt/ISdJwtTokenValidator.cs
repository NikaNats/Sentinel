namespace Sentinel.SdJwt;

/// <summary>
///     Provides token validation capabilities for SD-JWT presentation verification.
///     Implementations handle signature verification, issuer validation, and audience checks.
/// </summary>
public interface ISdJwtTokenValidator
{
    /// <summary>
    ///     Validates an issuer-signed SD-JWT token.
    /// </summary>
    /// <param name="issuerJwt">The issuer-signed JWT portion of the SD-JWT presentation.</param>
    /// <param name="expectedAudience">The audience the token should be issued for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Validation result containing the parsed token or error details.</returns>
    Task<SdJwtIssuerTokenValidationResult> ValidateIssuerTokenAsync(
        string issuerJwt,
        string expectedAudience,
        CancellationToken cancellationToken = default);
}
