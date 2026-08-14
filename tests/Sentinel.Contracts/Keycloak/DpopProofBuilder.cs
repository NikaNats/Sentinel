using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sentinel.Contracts.Keycloak;

/// <summary>
///     Builds RFC 9449 DPoP proofs for the contract suite's token requests.
///     Keycloak's realm client policy requires DPoP-bound tokens, so every
///     token-endpoint call signs a proof with the same static key to keep the
///     refresh binding valid.
/// </summary>
internal static class DpopProofBuilder
{
    private static readonly RSA Key = RSA.Create(2048);

    public static string CreateProof(string htu)
    {
        var parameters = Key.ExportParameters(false);

        var header = JsonSerializer.Serialize(new DpopProofHeaderContract(
            "dpop+jwt",
            "RS256",
            new DpopProofJwkContract(
                "RSA",
                Base64Url(parameters.Modulus!),
                Base64Url(parameters.Exponent!),
                "RS256",
                "sig")), KeycloakContractJsonContext.Default.DpopProofHeaderContract);

        var payload = JsonSerializer.Serialize(new DpopProofPayloadContract(
            "POST",
            htu,
            Guid.NewGuid().ToString(),
            DateTimeOffset.UtcNow.ToUnixTimeSeconds()), KeycloakContractJsonContext.Default.DpopProofPayloadContract);

        var header64 = Base64Url(Encoding.UTF8.GetBytes(header));
        var payload64 = Base64Url(Encoding.UTF8.GetBytes(payload));
        var signingInput = $"{header64}.{payload64}";

        var signature = Key.SignData(
            Encoding.UTF8.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        return $"{signingInput}.{Base64Url(signature)}";
    }

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}