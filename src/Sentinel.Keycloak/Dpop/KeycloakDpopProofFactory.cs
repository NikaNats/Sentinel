// Sentinel Security API - FAPI 2.0 Compliant

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sentinel.Keycloak.Dpop;

/// <summary>
///     Creates RFC 9449 DPoP proofs for the Sentinel runtime's own token-endpoint
///     calls (client_credentials, UMA ticket, token exchange, refresh).
///     Keycloak's realm client policy requires a DPoP proof on every token
///     request, so each outbound token call is signed with the shared process
///     proof key (PS256, the FAPI 2.0 baseline algorithm).
/// </summary>
public sealed class KeycloakDpopProofFactory(TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    // A single proof key per process keeps refresh-token binding valid: the
    // same key must sign every token-endpoint call for the same client.
    private static readonly RSA ProofKey = RSA.Create(2048);

    /// <summary>
    ///     Produces a DPoP proof JWT for <paramref name="httpMethod"/> at
    ///     <paramref name="htu"/> (RFC 9449 §2.1).
    /// </summary>
    /// <param name="httpMethod">HTTP method of the token request (POST).</param>
    /// <param name="htu">HTTP target URI of the token request.</param>
    /// <param name="accessToken">
    ///     When refreshing, the access token to stamp as the RFC 9449 <c>ath</c>
    ///     claim; otherwise <see langword="null"/>.
    /// </param>
    public string CreateProof(string httpMethod, string htu, string? accessToken = null)
    {
        var parameters = ProofKey.ExportParameters(false);

        var header = JsonSerializer.Serialize(new DpopProofHeaderDto(
            "dpop+jwt",
            "PS256",
            new DpopProofJwkDto(
                "RSA",
                Base64Url(parameters.Modulus!),
                Base64Url(parameters.Exponent!),
                "PS256",
                "sig")), KeycloakJsonContext.Default.DpopProofHeaderDto);

        var payload = new Dictionary<string, object>
        {
            ["htm"] = httpMethod,
            ["htu"] = htu,
            ["jti"] = Guid.NewGuid().ToString(),
            ["iat"] = _time.GetUtcNow().ToUnixTimeSeconds()
        };
        if (accessToken is not null)
        {
            payload["ath"] = Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(accessToken)));
        }

        var payloadJson = JsonSerializer.Serialize(payload, KeycloakJsonContext.Default.DictionaryStringObject);

        var header64 = Base64Url(Encoding.UTF8.GetBytes(header));
        var payload64 = Base64Url(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = $"{header64}.{payload64}";

        var signature = ProofKey.SignData(
            Encoding.UTF8.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);

        return $"{signingInput}.{Base64Url(signature)}";
    }

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}