using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Results;

namespace Sentinel.Application.Common.Abstractions;

/// <summary>
/// Adapter methods to bridge new Security.Abstractions APIs to older Application layer interface expectations.
/// Used during transition to new interface signatures. Remove post-v1.0.
/// </summary>
public static class SecurityAbstractionsAdapters
{
    /// <summary>
    /// Converts DpopValidationSuccess to legacy DpopValidationResult format.
    /// </summary>
    public static DpopValidationResult ToLegacyResult(this SecurityResult<DpopValidationSuccess> result)
    {
        return new DpopValidationResult
        {
            IsValid = result.IsSuccess,
            NewNonce = result.IsSuccess ? result.Value.Thumbprint : string.Empty,  // Note: using thumbprint as substitute
            Error = result.IsSuccess ? string.Empty : result.ErrorMessage ?? "unknown_error"
        };
    }

    /// <summary>
    /// Adapter for TryStoreNonceAsync using new SetNonceAsync API.
    /// </summary>
    public static async Task<bool> TryStoreNonceAsync(
        this IDpopNonceStore store,
        string thumbprint,
        string nonce,
        TimeSpan ttl,
        CancellationToken ct)
    {
        try
        {
            await store.SetNonceAsync(thumbprint, nonce, DateTimeOffset.UtcNow.Add(ttl), ct);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Adapter for ConsumeNonceIfMatchesAsync using new GetNonceAsync API.
    /// </summary>
    public static async Task<bool> ConsumeNonceIfMatchesAsync(
        this IDpopNonceStore store,
        string thumbprint,
        string expectedNonce,
        CancellationToken ct)
    {
        try
        {
            var nonce = await store.GetNonceAsync(thumbprint, ct);
            if (nonce == expectedNonce)
            {
                // Clear the nonce by setting it to empty
                await store.SetNonceAsync(thumbprint, string.Empty, DateTimeOffset.UtcNow, ct);
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }
}
