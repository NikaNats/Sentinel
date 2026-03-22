namespace Sentinel.Security.Abstractions.Token;

/// <summary>
/// Exchanges external provider tokens (federation, OAuth) for Sentinel access tokens.
/// Supports DPoP-bound tokens and external identity federation scenarios.
/// </summary>
public interface ITokenExchangeService
{
    /// <summary>
    /// Exchanges an external identity provider token for a Sentinel access token.
    /// </summary>
    /// <param name="externalToken">The external provider's token (JWT or opaque).</param>
    /// <param name="providerName">The external provider identifier (e.g., "google", "saml").</param>
    /// <param name="dpopProof">RFC 9449 DPoP proof binding token to client certificate/key.</param>
    /// <param name="codeVerifier">RFC 7636 PKCE code verifier for authorization code exchange.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Token exchange result or null if exchange fails.</returns>
    Task<TokenExchangeServiceResult?> ExchangeExternalTokenAsync(
        string externalToken,
        string providerName,
        string dpopProof,
        string codeVerifier,
        CancellationToken ct);
}

/// <summary>
/// Result of a token exchange operation.
/// </summary>
public sealed record TokenExchangeServiceResult(
    bool IsSuccess,
    bool IsUnauthorized,
    string? AccessToken,
    int? ExpiresIn,
    string? RefreshToken,
    string? Error);
