namespace Sentinel.Security.Abstractions.Token;

/// <summary>
/// Refreshes expired access tokens using refresh tokens.
/// Detects refresh token reuse attacks and enforces rotation.
/// </summary>
public interface ITokenRefreshService
{
    /// <summary>
    /// Refreshes an expired access token using a valid refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token (typically long-lived, secure-storage protected).</param>
    /// <param name="dpopProof">RFC 9449 DPoP proof binding token to client certificate/key.</param>
    /// <param name="clientIpHash">Hash of client IP for replay/reuse detection.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Token refresh result with new access/refresh tokens or reuse detection flag.</returns>
    Task<TokenRefreshServiceResult> RefreshTokenAsync(
        string refreshToken,
        string dpopProof,
        string clientIpHash,
        CancellationToken ct);
}

/// <summary>
/// Result of a token refresh operation.
/// </summary>
public sealed record TokenRefreshServiceResult(
    bool IsSuccess,
    string? AccessToken,
    string? RefreshToken,
    bool IsReuseDetected);
