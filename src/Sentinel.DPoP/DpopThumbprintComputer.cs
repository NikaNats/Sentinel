namespace Sentinel.DPoP;

/// <summary>
///     Computes RFC 7638 JWK thumbprints for DPoP key binding per RFC 9449.
/// </summary>
internal sealed class DpopThumbprintComputer : IDpopThumbprintComputer
{
    /// <summary>
    ///     Computes the RFC 7638 thumbprint from a JsonElement representing a public key.
    /// </summary>
    /// <remarks>
    ///     ✅ FIX: Uses source-generated context to guarantee Native AOT compliance.
    ///     Reflection-based serialization is blocked in trimmed environments.
    /// </remarks>
    /// <param name="jwk">JsonElement containing a JWK (e.g., from a JWT header).</param>
    /// <returns>Base64url-encoded thumbprint string, or empty string if JWK is unsupported.</returns>
    public string Compute(JsonElement jwk)
    {
        Dictionary<string, string> members;

        // EC (NIST curves): crv, kty, x, y
        if (jwk.TryGetProperty("kty", out var ktyElement)
            && string.Equals(ktyElement.GetString(), "EC", StringComparison.Ordinal)
            && jwk.TryGetProperty("crv", out var crv)
            && jwk.TryGetProperty("x", out var x)
            && jwk.TryGetProperty("y", out var y))
        {
            members = new Dictionary<string, string>
            {
                ["crv"] = crv.GetString() ?? string.Empty,
                ["kty"] = "EC",
                ["x"] = x.GetString() ?? string.Empty,
                ["y"] = y.GetString() ?? string.Empty
            };
        }
        // RSA: e, kty, n
        else if (jwk.TryGetProperty("kty", out var rsaKty)
                 && string.Equals(rsaKty.GetString(), "RSA", StringComparison.Ordinal)
                 && jwk.TryGetProperty("e", out var e)
                 && jwk.TryGetProperty("n", out var n))
        {
            members = new Dictionary<string, string>
            {
                ["e"] = e.GetString() ?? string.Empty,
                ["kty"] = "RSA",
                ["n"] = n.GetString() ?? string.Empty
            };
        }
        // ML-DSA (post-quantum): kty, x
        else if (jwk.TryGetProperty("kty", out var mlDsaKty)
                 && string.Equals(mlDsaKty.GetString(), "ML-DSA", StringComparison.Ordinal)
                 && jwk.TryGetProperty("x", out var mlDsaX))
        {
            members = new Dictionary<string, string>
            {
                ["kty"] = "ML-DSA",
                ["x"] = mlDsaX.GetString() ?? string.Empty
            };
        }
        else
        {
            return string.Empty;
        }

        // ✅ FIX: Use source-generated context (DpopJsonContext.Default.DictionaryStringString)
        // This eliminates reflection and guarantees Native AOT compatibility
        var canonical = JsonSerializer.Serialize(members, DpopJsonContext.Default.DictionaryStringString);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncoder.Encode(hash);
    }
}
