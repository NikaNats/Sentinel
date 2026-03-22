using System.Security.Claims;

namespace Sentinel.Security.Abstractions.SdJwt;

/// <summary>
/// Verifies Selective Disclosure JWTs (ISO/IEC 23328-2).
/// </summary>
public interface ISdJwtVerifier
{
    /// <summary>
    /// Verifies an SD-JWT presentation (with optional key binding).
    /// </summary>
    /// <param name="sdJwtPresentation">The complete SD-JWT presentation string.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>ClaimsPrincipal if verification succeeds, or failure result.</returns>
    Task<Results.SecurityResult<ClaimsPrincipal>> VerifyPresentationAsync(
        string sdJwtPresentation,
        CancellationToken cancellationToken = default);
}
