using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Sentinel.Security.Abstractions.Pqc;

namespace Sentinel.Infrastructure.Cryptography;

/// <summary>
///     2026 Enterprise Standard: Native Post-Quantum Cryptography (PQC) Verifier.
///     Implements FIPS 204 Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
///     Ensures that Sentinel API is mathematically protected against quantum computer attacks.
/// </summary>
public sealed class MlDsaSignatureVerifier(ILogger<MlDsaSignatureVerifier> logger) : IMlDsaSignatureVerifier
{
    private readonly ILogger<MlDsaSignatureVerifier>
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    public bool Verify(string algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> signature)
    {
        if (!MLDsa.IsSupported)
        {
            _logger.LogCritical(
                "CRITICAL SECURITY ALERT: ML-DSA (Post-Quantum) verification attempted, but the current OS platform does not support FIPS 204. Failing closed.");
            return false;
        }

        if (!TryMapAlgorithm(algorithm, out var mlDsaAlgorithm))
        {
            _logger.LogWarning("Unsupported ML-DSA algorithm name: {Algorithm}", algorithm);
            return false; // Fail-Closed
        }

        try
        {
            using var mldsa = MLDsa.ImportMLDsaPublicKey(mlDsaAlgorithm, publicKey);

            var isValid = mldsa.VerifyData(input, signature);

            if (isValid)
            {
                _logger.LogDebug("Quantum-Resistant ML-DSA signature verified successfully for {Algorithm}", algorithm);
            }
            else
            {
                _logger.LogWarning("ML-DSA signature verification failed. Possible forgery attempt detected.");
            }

            return isValid;
        }
        catch (CryptographicException ex)
        {
            _logger.LogWarning(ex, "Cryptography platform error during ML-DSA validation for algorithm {Algorithm}.",
                algorithm);
            return false;
        }
        catch (ArgumentException ex)
        {
            _logger.LogWarning(ex, "Invalid cryptographic key or data arguments provided for ML-DSA verifier.");
            return false;
        }
    }

    private static bool TryMapAlgorithm(string algorithm, [NotNullWhen(true)] out MLDsaAlgorithm? mlDsaAlgorithm)
    {
        mlDsaAlgorithm = null;

        switch (algorithm.ToUpperInvariant())
        {
            case "ML-DSA-44":
            case "MLDSA44":
                mlDsaAlgorithm = MLDsaAlgorithm.MLDsa44;
                return true;

            case "ML-DSA-65":
            case "MLDSA65":
                mlDsaAlgorithm = MLDsaAlgorithm.MLDsa65;
                return true;

            case "ML-DSA-87":
            case "MLDSA87":
                mlDsaAlgorithm = MLDsaAlgorithm.MLDsa87;
                return true;

            default:
                return false;
        }
    }
}
