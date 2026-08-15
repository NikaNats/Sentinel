using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.Tests.Integration.Federation;

/// <summary>
///     RFC 9449 DPoP proof builder for the FAPI 2.0 browser flow tests.
///     Each instance owns an ephemeral ES256 (P-256) key so every test run
///     exercises a fresh DPoP key pair (RFC 9449 security consideration: keys
///     must be single-use per context).
/// </summary>
public sealed class Fapi2DpopProofBuilder : IDisposable
{
    private readonly ECDsa _privateKey;
    private readonly ECDsaSecurityKey _securityKey;
    private readonly JsonWebKey _publicJwk;

    public Fapi2DpopProofBuilder()
    {
        _privateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _securityKey = new ECDsaSecurityKey(_privateKey);
        _publicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(_securityKey);
        JwkThumbprint = ComputeJwkThumbprint(_publicJwk);
    }

    public string JwkThumbprint { get; }

    public string BuildTokenEndpointProof(string tokenEndpointUrl, string? nonce = null, string? explicitJti = null)
        => BuildProof("POST", tokenEndpointUrl, nonce, accessToken: null, explicitJti);

    public string BuildResourceRequestProof(
        string httpMethod, string resourceUrl, string accessToken,
        string? nonce = null, string? explicitJti = null)
        => BuildProof(httpMethod, resourceUrl, nonce, accessToken, explicitJti);

    private string BuildProof(string httpMethod, string url, string? nonce, string? accessToken, string? explicitJti)
    {
        var claims = new Dictionary<string, object>
        {
            ["jti"] = explicitJti ?? Guid.NewGuid().ToString("N"),
            ["htm"] = httpMethod.ToUpperInvariant(),
            ["htu"] = NormalizeUrl(url),
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        if (!string.IsNullOrEmpty(nonce))
        {
            claims["nonce"] = nonce;
        }

        if (!string.IsNullOrEmpty(accessToken))
        {
            // ath: base64url(SHA-256(access_token)) - binds the proof to the token.
            claims["ath"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(accessToken)));
        }

        var handler = new JsonWebTokenHandler();
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            TokenType = "dpop+jwt",
            SigningCredentials = new SigningCredentials(_securityKey, SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = new Dictionary<string, string>
                {
                    ["kty"] = _publicJwk.Kty!,
                    ["crv"] = _publicJwk.Crv!,
                    ["x"] = _publicJwk.X!,
                    ["y"] = _publicJwk.Y!
                }
            }
        };

        return handler.CreateToken(descriptor);
    }

    /// <summary>RFC 9449: htu is scheme + host + path, no query or fragment.</summary>
    private static string NormalizeUrl(string url)
    {
        var uri = new Uri(url);
        return $"{uri.Scheme}://{uri.Authority}{uri.AbsolutePath}";
    }

    /// <summary>RFC 7638: SHA-256 of the canonical JWK member set (crv, kty, x, y).</summary>
    private static string ComputeJwkThumbprint(JsonWebKey jwk)
    {
        var canonical = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        });
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    public void Dispose() => _privateKey.Dispose();
}
