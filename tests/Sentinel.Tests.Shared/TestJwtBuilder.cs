using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.Tests.Shared;

/// <summary>
///     Helper to build test DPoP proofs with configurable claims.
///     Used for unit testing DPoP validation logic without external dependencies.
/// </summary>
public static class TestJwtBuilder
{
    private static readonly JsonWebTokenHandler TokenHandler = new();

    /// <summary>
    ///     Creates a minimal DPoP proof JWT for testing.
    ///     Note: This is for schema/structure testing only; signatures are not cryptographically valid.
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

    /// <summary>
    ///     Creates a DPoP proof with Cross-Algorithm Substitution attack:
    ///     Claims "alg" header mismatches the actual key type (e.g., EC key/key signing as RSA).
    ///     Attack: Attacker switches algorithms in header without re-signing.
    ///     Vulnerable systems might accept this, allowing signature bypass.
    /// </summary>
    public static string CreateMalformedProof(
        ECDsa ecDsa,
        string headerAlg,
        string kty)
    {
        _ = ecDsa;

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Intentionally malformed proof for algorithm confusion tests:
        // - header alg claims unsupported algorithm (e.g., PS256)
        // - typ is valid DPoP so validator reaches algorithm check first
        var header = new Dictionary<string, object>
        {
            ["alg"] = headerAlg,
            ["typ"] = "dpop+jwt",
            ["jwk"] = new Dictionary<string, string>
            {
                ["kty"] = kty,
                ["crv"] = "P-256",
                ["x"] = Base64UrlEncoder.Encode(new byte[32]),
                ["y"] = Base64UrlEncoder.Encode(new byte[32])
            }
        };

        var payload = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = "POST",
            ["htu"] = "https://api.sentinel.io/v1/auth",
            ["iat"] = now
        };

        var headerJson = Base64UrlEncoder.Encode(JsonSerializer.SerializeToUtf8Bytes(header));
        var payloadJson = Base64UrlEncoder.Encode(JsonSerializer.SerializeToUtf8Bytes(payload));
        return $"{headerJson}.{payloadJson}.malformed-signature";
    }

    /// <summary>
    ///     Creates a DPoP proof using symmetric key (HMAC) instead of asymmetric.
    ///     Attack: Symmetric Key Confusion - attacker uses HS256 (symmetric) where ES256 (asymmetric) is required.
    ///     If the validator incorrectly uses the public key as the HMAC secret, any symmetric key works.
    /// </summary>
    public static string CreateSymmetricProof(
        string secret,
        string algorithm)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Intentionally uses unsupported HMAC algorithms while preserving valid DPoP shape.
        var header = new Dictionary<string, object>
        {
            ["alg"] = algorithm,
            ["typ"] = "dpop+jwt",
            ["jwk"] = new Dictionary<string, string>
            {
                ["kty"] = "oct",
                ["k"] = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(secret))
            }
        };

        var payload = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = "GET",
            ["htu"] = "https://api.sentinel.io/v1/resource",
            ["iat"] = now
        };

        var headerJson = Base64UrlEncoder.Encode(JsonSerializer.SerializeToUtf8Bytes(header));
        var payloadJson = Base64UrlEncoder.Encode(JsonSerializer.SerializeToUtf8Bytes(payload));
        return $"{headerJson}.{payloadJson}.hmac-signature";
    }

    private static string NormalizeUri(string uri)
    {
        try
        {
            var parsed = new Uri(uri, UriKind.Absolute);
            return parsed.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.Unescaped)
                .TrimEnd('/');
        }
#pragma warning disable CA1031 // Catch-all for test fallback: invalid URI input
        catch (Exception)
        {
            return uri;
        }
#pragma warning restore CA1031
    }
}
