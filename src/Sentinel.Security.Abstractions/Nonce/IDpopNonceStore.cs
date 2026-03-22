namespace Sentinel.Security.Abstractions.Nonce;

/// <summary>
/// Per-client DPoP nonce store for RFC 9449 §4.3 nonce challenge-response.
/// Keyed by JWK thumbprint (client identity).
/// </summary>
public interface IDpopNonceStore
{
    /// <summary>
    /// Retrieves the current nonce for a given client (identified by JWK thumbprint).
    /// </summary>
    /// <param name="thumbprint">JWK thumbprint (RFC 7638) identifying the client.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The nonce value if one exists and is valid, null otherwise.</returns>
    /// <exception cref="Exceptions.NonceStoreUnavailableException">Thrown if the store is unreachable.</exception>
    Task<string?> GetNonceAsync(string thumbprint, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores a new nonce for a client, invalidating any prior nonce.
    /// </summary>
    /// <param name="thumbprint">JWK thumbprint identifying the client.</param>
    /// <param name="nonce">The new nonce value.</param>
    /// <param name="expiresAt">UTC time when this nonce expires.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="Exceptions.NonceStoreUnavailableException">Thrown if the store is unreachable.</exception>
    Task SetNonceAsync(string thumbprint, string nonce, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes expired nonce entries (garbage collection).
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="Exceptions.NonceStoreUnavailableException">Thrown if the store is unreachable.</exception>
    Task CleanupExpiredAsync(CancellationToken cancellationToken = default);
}
