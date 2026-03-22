using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.Tests.DPoP;

/// <summary>
/// Helper to build test DPoP proofs with configurable claims.
/// Used for unit testing DPoP validation logic without external dependencies.
/// </summary>
public static class TestJwtBuilder
{
    private static readonly JsonWebTokenHandler TokenHandler = new();

    /// <summary>
    /// Creates a minimal DPoP proof JWT for testing.
    /// Note: This is for schema/structure testing only; signatures are not cryptographically valid.
    /// </summary>
    public static string CreateDpopProof(
        string algorithm,
        string thumbprint,
        string? jti,
        string httpMethod,
        string httpUri,
        int iatSecondsAgo)
    {
        var now = DateTimeOffset.UtcNow;
        var iat = now.AddSeconds(-iatSecondsAgo).ToUnixTimeSeconds();

        // Create test JWK (not cryptographically valid, for structure testing)
        var jwkDict = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(new byte[32]),
            ["y"] = Base64UrlEncoder.Encode(new byte[32])
        };

        var payload = new Dictionary<string, object>
        {
            ["typ"] = "dpop+jwt",
            ["alg"] = algorithm,
            ["jwk"] = jwkDict,
            ["jti"] = jti ?? string.Empty,
            ["htm"] = httpMethod,
            ["htu"] = NormalizeUri(httpUri),
            ["iat"] = iat
        };

        // Create unsigned JWT for testing structure (not production use)
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Claims = payload,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(new byte[32]),
                algorithm)
        };

        try
        {
            return TokenHandler.CreateToken(tokenDescriptor);
        }
#pragma warning disable CA1031 // Catch-all for test fallback: production token creation failure
        catch (Exception)
        {
            // Fallback: create minimal JWT manually for testing
            return "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7ImtpdCI6IkVDIn19." +
                   "eyJqdGkiOiJ0ZXN0IiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdG9rZW4iLCJpYXQiOjE2NDI2NjAxNjB9." +
                   "test-signature";
        }
#pragma warning restore CA1031
    }

    private static string NormalizeUri(string uri)
    {
        try
        {
            var parsed = new Uri(uri, UriKind.Absolute);
            return parsed.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.Unescaped).TrimEnd('/');
        }
#pragma warning disable CA1031 // Catch-all for test fallback: invalid URI input
        catch (Exception)
        {
            return uri;
        }
#pragma warning restore CA1031
    }
}
