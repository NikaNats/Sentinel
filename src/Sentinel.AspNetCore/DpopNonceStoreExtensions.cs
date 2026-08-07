using Sentinel.Security.Abstractions.Nonce;

namespace Sentinel.AspNetCore;

/// <summary>
///     Internal extensions for IDpopNonceStore to bridge between legacy convenience methods
///     and new abstraction APIs. For use by AspNetCore middleware only.
///     SECURITY INVARIANT: Infrastructure exceptions are deliberately NOT swallowed here.
///     A store outage (<see cref="Sentinel.Security.Abstractions.Exceptions.NonceStoreUnavailableException" />)
///     propagates to <c>DpopValidationMiddleware</c>, which fails closed with HTTP 503 + Retry-After
///     instead of being misinterpreted as a benign client-side nonce mismatch (HTTP 401).
/// </summary>
internal static class DpopNonceStoreExtensions
{
    /// <summary>
    ///     Stores a nonce for a given thumbprint with a specified TTL.
    /// </summary>
    /// <param name="store">The DPoP nonce store instance.</param>
    /// <param name="thumbprint">JWK thumbprint identifying the client.</param>
    /// <param name="nonce">The cryptographic nonce to store.</param>
    /// <param name="ttl">Time-to-live duration for the nonce.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if storage completed successfully.</returns>
    /// <exception cref="Sentinel.Security.Abstractions.Exceptions.NonceStoreUnavailableException">
    ///     Thrown when the backing store is unreachable; caller MUST fail closed.
    /// </exception>
    public static async Task<bool> TryStoreNonceAsync(
        this IDpopNonceStore store,
        string thumbprint,
        string nonce,
        TimeSpan ttl,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint);
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);

        await store.SetNonceAsync(thumbprint, nonce, DateTimeOffset.UtcNow.Add(ttl), ct).ConfigureAwait(false);
        return true;
    }
}
