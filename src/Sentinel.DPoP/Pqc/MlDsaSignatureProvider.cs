using Sentinel.Security.Abstractions.Pqc;

namespace Sentinel.DPoP.Pqc;

internal sealed class MlDsaSignatureProvider(MlDsaSecurityKey key, string algorithm, IMlDsaSignatureVerifier verifier)
    : SignatureProvider(key, algorithm)
{
    private readonly byte[] _publicKey = key.PublicKeyBytes;

    public override bool Verify(byte[] input, byte[] signature) =>
        verifier.Verify(Algorithm, _publicKey, input, signature);

    public override bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset,
        int signatureLength)
    {
        var inputSpan = new ReadOnlySpan<byte>(input, inputOffset, inputLength);
        var signatureSpan = new ReadOnlySpan<byte>(signature, signatureOffset, signatureLength);

        return verifier.Verify(Algorithm, _publicKey, inputSpan, signatureSpan);
    }

    public override byte[] Sign(byte[] input) =>
        throw new NotSupportedException("DPoP Validator does not sign tokens.");

    protected override void Dispose(bool disposing)
    {
    }
}
