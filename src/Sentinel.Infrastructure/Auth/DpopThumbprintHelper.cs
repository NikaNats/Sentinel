// Sentinel Security API - FAPI 2.0 Compliant
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.Infrastructure.Auth;

public static class DpopThumbprintHelper
{
    public static string ComputeJwkThumbprint(JsonElement jwk)
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

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncoder.Encode(hash);
    }
}
