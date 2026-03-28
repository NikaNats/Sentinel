namespace Sentinel.SdJwt;

/// <summary>
///     Abstraction for processing and verifying Selective Disclosure JWT (SD-JWT) presentations (RFC 9901).
///     Enables dependency injection and testability through interface-based design.
/// </summary>
public interface ISdJwtPresenter
{
    /// <summary>
    ///     Verifies an SD-JWT presentation with optional key binding.
    /// </summary>
    /// <remarks>
    ///     SD-JWT presentation format: issuer_jwt~disclosure1~disclosure2~...~key_binding_jwt
    ///     Verification process:
    ///     1. Parses presentation format (issuer JWT, disclosures, key binding JWT)
    ///     2. Validates issuer token signature and claims
    ///     3. Validates key binding JWT signature, age, and sd_hash
    ///     4. Reconstructs claims from disclosures based on _sd digests
    ///     5. Returns ClaimsPrincipal with disclosed claims
    /// </remarks>
    /// <param name="sdJwtPresentation">Complete SD-JWT presentation string with ~ separators.</param>
    /// <param name="expectedAudience">Expected audience for token validation.</param>
    /// <param name="expectedNonce">Optional nonce to validate in key binding token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Verification result with principal or error details.</returns>
    Task<SdJwtVerificationResult> VerifyPresentationAsync(
        string sdJwtPresentation,
        string expectedAudience,
        string? expectedNonce = null,
        CancellationToken cancellationToken = default);
}
