using Microsoft.IdentityModel.Tokens;

namespace Sentinel.Security.Abstractions.Pqc;

/// <summary>
///     Post-Quantum ML-DSA (FIPS 204) Security Key.
/// </summary>
public sealed class MlDsaSecurityKey(byte[] publicKeyBytes, string algorithm) : SecurityKey
{
    public byte[] PublicKeyBytes { get; } = publicKeyBytes ?? throw new ArgumentNullException(nameof(publicKeyBytes));
    public string Algorithm { get; } = algorithm ?? throw new ArgumentNullException(nameof(algorithm));

    public override int KeySize => PublicKeyBytes.Length * 8;
}

public interface IMlDsaSignatureVerifier
{
    bool Verify(string algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature);
}
