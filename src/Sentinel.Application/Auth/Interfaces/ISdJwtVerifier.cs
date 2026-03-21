using Sentinel.Application.Auth.Models;

namespace Sentinel.Application.Auth.Interfaces;

public interface ISdJwtVerifier
{
    Task<SdJwtVerificationResult> VerifyPresentationAsync(
        string sdJwtPresentation,
        string expectedAudience,
        string? expectedNonce,
        CancellationToken ct);
}
