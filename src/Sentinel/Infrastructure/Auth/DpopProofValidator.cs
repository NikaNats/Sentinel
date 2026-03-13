using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Infrastructure.Cache;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sentinel.Infrastructure.Auth;

public interface IDpopProofValidator
{
    Task<DpopValidationResult> ValidateAsync(string dpopHeader, string accessToken, string httpMethod, string httpUrl, CancellationToken ct);
}

public sealed class DpopValidationResult
{
    public bool IsValid { get; set; }
    public string NewNonce { get; set; } = string.Empty;
}

public sealed class DpopProofValidator(IJtiReplayCache replayCache) : IDpopProofValidator
{
    private static readonly JsonWebTokenHandler TokenHandler = new();

    public async Task<DpopValidationResult> ValidateAsync(string dpopHeader, string accessToken, string httpMethod, string httpUrl, CancellationToken ct)
    {
        var result = new DpopValidationResult { IsValid = false };

        if (!TokenHandler.CanReadToken(dpopHeader) || !TokenHandler.CanReadToken(accessToken))
        {
            return result;
        }

        var dpopToken = TokenHandler.ReadJsonWebToken(dpopHeader);

        if (!string.Equals(dpopToken.Alg, SecurityAlgorithms.RsaSsaPssSha256, StringComparison.Ordinal)
            && !string.Equals(dpopToken.Alg, SecurityAlgorithms.EcdsaSha256, StringComparison.Ordinal))
        {
            return result;
        }

        if (!string.Equals(dpopToken.Typ, "dpop+jwt", StringComparison.OrdinalIgnoreCase))
        {
            return result;
        }

        if (!dpopToken.TryGetHeaderValue<object>("jwk", out var jwkObj) || jwkObj is null)
        {
            return result;
        }

        var jwkJson = jwkObj.ToString();
        if (string.IsNullOrWhiteSpace(jwkJson))
        {
            return result;
        }

        using var jwkDoc = JsonDocument.Parse(jwkJson);
        var jwkElement = jwkDoc.RootElement;

        if (jwkElement.TryGetProperty("d", out _))
        {
            return result;
        }

        if (!await ValidateDpopSignatureAsync(dpopHeader, jwkJson, dpopToken.Alg))
        {
            return result;
        }

        if (!dpopToken.TryGetPayloadValue<string>("jti", out var jti) || string.IsNullOrWhiteSpace(jti))
        {
            return result;
        }

        if (!dpopToken.TryGetPayloadValue<string>("htm", out var htm)
            || !string.Equals(htm, httpMethod, StringComparison.OrdinalIgnoreCase))
        {
            return result;
        }

        if (!dpopToken.TryGetPayloadValue<string>("htu", out var htu)
            || !string.Equals(NormalizeUri(htu), NormalizeUri(httpUrl), StringComparison.Ordinal))
        {
            return result;
        }

        if (!dpopToken.TryGetPayloadValue<long>("iat", out var iat))
        {
            return result;
        }

        var iatTime = DateTimeOffset.FromUnixTimeSeconds(iat);
        var now = DateTimeOffset.UtcNow;
        if (iatTime < now.AddSeconds(-60) || iatTime > now.AddSeconds(5))
        {
            return result;
        }

        var accessJwt = TokenHandler.ReadJsonWebToken(accessToken);
        if (!accessJwt.TryGetPayloadValue<JsonElement>("cnf", out var cnf)
            || !cnf.TryGetProperty("jkt", out var jktElement)
            || string.IsNullOrWhiteSpace(jktElement.GetString()))
        {
            return result;
        }

        var expectedJkt = ComputeJwkThumbprint(jwkElement);
        if (!string.Equals(jktElement.GetString(), expectedJkt, StringComparison.Ordinal))
        {
            return result;
        }

        var isReplayed = await replayCache.ExistsAsync($"dpop:{jti}", ct);
        if (isReplayed)
        {
            return result;
        }

        await replayCache.StoreAsync($"dpop:{jti}", TimeSpan.FromMinutes(2), ct);

        result.IsValid = true;
        result.NewNonce = GenerateNewNonce();
        return result;
    }

    private static async Task<bool> ValidateDpopSignatureAsync(string token, string jwkJson, string algorithm)
    {
        JsonWebKey signingKey;

        try
        {
            signingKey = JsonWebKey.Create(jwkJson);
        }
        catch
        {
            return false;
        }

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            RequireSignedTokens = true,
            ValidAlgorithms = [algorithm]
        };

        var validationResult = await TokenHandler.ValidateTokenAsync(token, validationParameters);
        return validationResult.IsValid;
    }

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

    private static string ComputeJwkThumbprint(JsonElement jwk)
    {
        string canonical;

        if (jwk.TryGetProperty("kty", out var ktyElement)
            && string.Equals(ktyElement.GetString(), "EC", StringComparison.Ordinal)
            && jwk.TryGetProperty("crv", out var crv)
            && jwk.TryGetProperty("x", out var x)
            && jwk.TryGetProperty("y", out var y))
        {
            canonical = JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["crv"] = crv.GetString() ?? string.Empty,
                ["kty"] = "EC",
                ["x"] = x.GetString() ?? string.Empty,
                ["y"] = y.GetString() ?? string.Empty
            });
        }
        else if (jwk.TryGetProperty("kty", out var rsaKty)
                 && string.Equals(rsaKty.GetString(), "RSA", StringComparison.Ordinal)
                 && jwk.TryGetProperty("e", out var e)
                 && jwk.TryGetProperty("n", out var n))
        {
            canonical = JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["e"] = e.GetString() ?? string.Empty,
                ["kty"] = "RSA",
                ["n"] = n.GetString() ?? string.Empty
            });
        }
        else
        {
            return string.Empty;
        }

        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncoder.Encode(hash);
    }

    private static string GenerateNewNonce()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncoder.Encode(bytes);
    }
}
