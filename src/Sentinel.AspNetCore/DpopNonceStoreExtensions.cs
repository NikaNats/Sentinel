using Sentinel.Security.Abstractions.Nonce;

namespace Sentinel.AspNetCore;

/// <summary>
///     Internal extensions for IDpopNonceStore to bridge between legacy convenience methods
///     and new abstraction APIs. For use by AspNetCore middleware only.
/// </summary>
internal static class DpopNonceStoreExtensions
{
    /// <summary>
    ///     Stores a nonce for a given thumbprint with a specified TTL.
    /// </summary>
#pragma warning disable CA1031 // Intentionally catches all exceptions from nonce storage to provide safe fallback
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
#pragma warning restore CA1031

    /// <summary>
    ///     Retrieves and validates a stored nonce, clearing it if it matches.
    /// </summary>
#pragma warning disable CA1031 // Intentionally catches all exceptions from nonce retrieval to provide safe fallback
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
#pragma warning restore CA1031
}
