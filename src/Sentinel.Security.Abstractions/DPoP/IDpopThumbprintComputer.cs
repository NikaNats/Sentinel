using System.Text.Json;

namespace Sentinel.Security.Abstractions.DPoP;

/// <summary>
///     Computes RFC 7638 JWK thumbprints for cryptographic key binding.
///     Used to derive stable, scheme-independent identifiers from public keys.
/// </summary>
public interface IDpopThumbprintComputer
{
    /// <summary>
    ///     Computes the RFC 7638 thumbprint from a JsonElement representing a public key.
    /// </summary>
    /// <param name="jwk">JsonElement containing a JWK (e.g., from a JWT header).</param>
    /// <returns>Base64url-encoded thumbprint string.</returns>
    string Compute(JsonElement jwk);
}
