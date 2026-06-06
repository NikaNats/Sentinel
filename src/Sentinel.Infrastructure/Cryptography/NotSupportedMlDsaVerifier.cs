using System;
using Microsoft.Extensions.Logging;
using Sentinel.Security.Abstractions.Pqc;

namespace Sentinel.Infrastructure.Cryptography;

internal sealed class NotSupportedMlDsaVerifier(ILogger<NotSupportedMlDsaVerifier> logger) : IMlDsaSignatureVerifier
{
    public bool Verify(string algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
    {
        logger.LogWarning("SECURITY ALERT: ML-DSA (Post-Quantum) signature verification attempted, but the mathematical backend is not yet installed. Request rejected securely (Fail-Closed). Algorithm: {Alg}", algorithm);
        return false;
    }
}
