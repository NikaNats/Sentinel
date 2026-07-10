using Sentinel.Security.Abstractions.Pqc;
using MlDsaSecurityKey = Sentinel.Security.Abstractions.Pqc.MlDsaSecurityKey;

namespace Sentinel.DPoP.Pqc;

public sealed class PqcCryptoProviderFactory(IMlDsaSignatureVerifier mlDsaVerifier) : CryptoProviderFactory
{
    private readonly IMlDsaSignatureVerifier _mlDsaVerifier = mlDsaVerifier ?? throw new ArgumentNullException(nameof(mlDsaVerifier));

    public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
    {
        if (key is MlDsaSecurityKey mlDsaKey && algorithm.StartsWith("ML-DSA-", StringComparison.OrdinalIgnoreCase))
        {
            return new MlDsaSignatureProvider(mlDsaKey, algorithm, _mlDsaVerifier);
        }

        return base.CreateForVerifying(key, algorithm);
    }

    public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
    {
        if (key is MlDsaSecurityKey && algorithm.StartsWith("ML-DSA-", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return base.IsSupportedAlgorithm(algorithm, key);
    }
}
