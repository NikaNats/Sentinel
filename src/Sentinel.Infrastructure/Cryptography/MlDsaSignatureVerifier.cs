using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Sentinel.Security.Abstractions.Pqc;

namespace Sentinel.Infrastructure.Cryptography;

/// <summary>
///     Enterprise-Grade Native Post-Quantum Cryptography (PQC) Verifier.
///     Implements FIPS 204 Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
///     Enforces native platform verification and fails closed under all error conditions.
/// </summary>
public sealed class MlDsaSignatureVerifier(ILogger<MlDsaSignatureVerifier> logger) : IMlDsaSignatureVerifier
{
    private readonly ILogger<MlDsaSignatureVerifier> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    // Optimized FrozenDictionary provides high-performance, read-only, collision-free O(1) lookups
    private static readonly FrozenDictionary<string, MLDsaAlgorithm> AlgorithmMap = new Dictionary<string, MLDsaAlgorithm>(StringComparer.OrdinalIgnoreCase)
    {
        { "ML-DSA-44", MLDsaAlgorithm.MLDsa44 },
        { "MLDSA44", MLDsaAlgorithm.MLDsa44 },
        { "ML-DSA-65", MLDsaAlgorithm.MLDsa65 },
        { "MLDSA65", MLDsaAlgorithm.MLDsa65 },
        { "ML-DSA-87", MLDsaAlgorithm.MLDsa87 },
        { "MLDSA87", MLDsaAlgorithm.MLDsa87 }
    }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    // Compiled structured logging delegates to completely eliminate string allocations on the hot path
    private static readonly Action<ILogger, Exception?> LogMissingAlgorithm =
        LoggerMessage.Define(LogLevel.Warning, new EventId(4001, "MlDsaMissingAlgorithm"), "ML-DSA verification failed: Algorithm identifier is null or empty.");

    private static readonly Action<ILogger, Exception?> LogPlatformUnsupported =
        LoggerMessage.Define(LogLevel.Critical, new EventId(4002, "MlDsaPlatformUnsupported"), "CRITICAL SECURITY ALERT: ML-DSA (Post-Quantum) verification was requested, but the host operating system platform lacks native FIPS 204 support. Failing closed.");

    private static readonly Action<ILogger, string, Exception?> LogUnsupportedAlgorithm =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(4003, "MlDsaUnsupportedAlgorithm"), "Unsupported ML-DSA algorithm specified: {Algorithm}");

    private static readonly Action<ILogger, string, Exception?> LogVerificationSuccess =
        LoggerMessage.Define<string>(LogLevel.Debug, new EventId(4005, "MlDsaVerificationSuccess"), "ML-DSA signature verified successfully for {Algorithm}");

    private static readonly Action<ILogger, Exception?> LogVerificationFailed =
        LoggerMessage.Define(LogLevel.Warning, new EventId(4006, "MlDsaVerificationFailed"), "ML-DSA signature verification failed. Possible payload alteration or signature forgery detected.");

    private static readonly Action<ILogger, Exception?> LogCryptoError =
        LoggerMessage.Define(LogLevel.Error, new EventId(4007, "MlDsaCryptoError"), "Native cryptographic platform error encountered during ML-DSA validation.");

    private static readonly Action<ILogger, Exception?> LogArgumentError =
        LoggerMessage.Define(LogLevel.Error, new EventId(4008, "MlDsaArgumentError"), "Invalid state or argument exception handled in ML-DSA verifier core.");

    public bool Verify(string algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
    {
        if (string.IsNullOrWhiteSpace(algorithm))
        {
            LogMissingAlgorithm(_logger, null);
            return false; // Fail-Closed
        }

        if (!MLDsa.IsSupported)
        {
            LogPlatformUnsupported(_logger, null);
            return false; // Fail-Closed
        }

        if (!TryMapAlgorithm(algorithm, out var mlDsaAlgorithm))
        {
            LogUnsupportedAlgorithm(_logger, algorithm, null);
            return false; // Fail-Closed
        }

        try
        {
            // Delegate key validation, size limits, and format verification to the native .NET 10 layer
            using var mldsa = MLDsa.ImportMLDsaPublicKey(mlDsaAlgorithm, publicKey);

            var isValid = mldsa.VerifyData(input, signature);

            if (isValid)
            {
                LogVerificationSuccess(_logger, algorithm, null);
            }
            else
            {
                LogVerificationFailed(_logger, null);
            }

            return isValid;
        }
        catch (CryptographicException ex)
        {
            LogCryptoError(_logger, ex);
            return false; // Fail-Closed (protects native resources on invalid size/format)
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            LogArgumentError(_logger, ex);
            return false; // Fail-Closed
        }
    }

    private static bool TryMapAlgorithm(string algorithm, [NotNullWhen(true)] out MLDsaAlgorithm? mlDsaAlgorithm)
    {
        return AlgorithmMap.TryGetValue(algorithm, out mlDsaAlgorithm);
    }
}
