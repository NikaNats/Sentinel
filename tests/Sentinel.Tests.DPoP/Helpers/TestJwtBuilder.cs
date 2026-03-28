using Microsoft.IdentityModel.JsonWebTokens;

namespace Sentinel.Tests.DPoP;

/// <summary>
///     Production-grade cryptographic helper for building mathematically valid DPoP proofs.
///     This test helper removes the "silent fail" anti-pattern and replaces it with:
///     - Real ECDsa P-256 signing with full cryptographic validity
///     - Explicit error handling (no catch-all fallbacks)
///     - Strict parameter validation
///     - RFC 9449 compliance verification
///     SECURITY PRINCIPLE: A test that fakes a signature is like a fire drill where nobody leaves the building.
///     This builder ensures the validator's internal TokenHandler is actually verifying real signatures.
/// </summary>
public static class TestJwtBuilder
{
    private static readonly JsonWebTokenHandler TokenHandler = new();

    /// <summary>
    ///     Creates a mathematically valid DPoP proof signed with real ECDsa P-256 cryptography.
    ///     ✅ PRODUCTION-GRADE: Every signature is cryptographically verifiable.
    /// </summary>
    /// <param name="signingKey">The ECDsa security key used for JOSE signing (typically from a test fixture).</param>
    /// <param name="algorithm">The signing algorithm (e.g., "ES256"). Must match the key type.</param>
    /// <param name="publicJwk">The public JWK to embed in the proof header (from ExportParameters(false)).</param>
    /// <param name="httpMethod">HTTP method (e.g., "POST", "GET") per RFC 9449 section 4.1.</param>
    /// <param name="httpUri">HTTP URI for the request. Must be absolute and normalized.</param>
    /// <param name="nonce">Optional server-issued nonce for proof binding. If provided, embedded in payload.</param>
    /// <param name="iat">Optional iat (issued-at) override for temporal boundary testing. Defaults to now.</param>
    /// <returns>
    ///     A valid, signed JWT in the format:
    ///     header.payload.signature
    ///     Where:
    ///     - header contains {"alg":"ES256","typ":"dpop+jwt","jwk":{...}}
    ///     - payload contains {"jti","htm","htu","iat" and optional "nonce"}
    ///     - signature is ECDSA(SHA256(header.payload), privateKey)
    /// </returns>
    public static string CreateValidProof(
        SecurityKey signingKey,
        string algorithm,
        Dictionary<string, object> publicJwk,
        string httpMethod,
        string httpUri,
        string? nonce = null,
        DateTimeOffset? iat = null)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentNullException.ThrowIfNull(algorithm);
        ArgumentNullException.ThrowIfNull(publicJwk);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpUri);

        // Validate URI is absolute
        _ = new Uri(httpUri, UriKind.Absolute); // Throws if malformed

        var now = DateTimeOffset.UtcNow;
        var issuedAt = (iat ?? now).ToUnixTimeSeconds();

        // Build RFC 9449 compliant payload
        var claims = new Dictionary<string, object>
        {
            // RFC 9449 section 4.1: mandatory claims
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = httpMethod,
            ["htu"] = NormalizeUri(httpUri),
            ["iat"] = issuedAt
        };

        // RFC 9449 section 5.1: optional nonce for request/response binding
        if (!string.IsNullOrEmpty(nonce))
        {
            claims["nonce"] = nonce;
        }

        // Create security token descriptor with explicit JOSE requirements
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(signingKey, algorithm),
            TokenType = "dpop+jwt"
        };

        // RFC 9449 section 4: inject the public JWK in the JOSE header
        descriptor.AdditionalHeaderClaims = new Dictionary<string, object>
        {
            ["jwk"] = publicJwk
        };

        // Perform actual ECDSA signing via Microsoft.IdentityModel
        return TokenHandler.CreateToken(descriptor);
    }

    /// <summary>
    ///     Normalizes a URI by removing query strings and fragments per RFC 9449.
    ///     Used internally for strict URI matching.
    /// </summary>
    private static string NormalizeUri(string uri)
    {
        var parsed = new Uri(uri, UriKind.Absolute);
        var builder = new UriBuilder(parsed)
        {
            Query = string.Empty,
            Fragment = string.Empty
        };

        return builder.Uri.AbsoluteUri.TrimEnd('/');
    }
}
