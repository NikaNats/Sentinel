using Sentinel.Security.Abstractions.Nonce;
using AppDpopNonceStore = Sentinel.Application.Common.Abstractions.IDpopNonceStore;
using SecDpopNonceStore = Sentinel.Security.Abstractions.Nonce.IDpopNonceStore;

namespace Sentinel.Tests.Shared.Fixtures;

/// <summary>
/// Adapter that bridges the Application-layer IDpopNonceStore interface to the Security-layer IDpopNonceStore.
/// Since the Application version inherits from the Security version, this adapter simply delegates all calls
/// to the underlying security implementation.
/// </summary>
public sealed class DpopNonceStoreAdapter : AppDpopNonceStore
{
    private readonly SecDpopNonceStore _securityNonceStore;

    public DpopNonceStoreAdapter(SecDpopNonceStore securityNonceStore)
    {
        _securityNonceStore = securityNonceStore ?? throw new ArgumentNullException(nameof(securityNonceStore));
    }

    /// <summary>
    /// Delegates to security nonce store's GetNonceAsync.
    /// </summary>
    public Task<string?> GetNonceAsync(string thumbprint, CancellationToken cancellationToken = default)
    {
        return _securityNonceStore.GetNonceAsync(thumbprint, cancellationToken);
    }

    /// <summary>
    /// Delegates to security nonce store's SetNonceAsync.
    /// </summary>
    public Task SetNonceAsync(string thumbprint, string nonce, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        return _securityNonceStore.SetNonceAsync(thumbprint, nonce, expiresAt, cancellationToken);
    }

    /// <summary>
    /// Delegates to security nonce store's CleanupExpiredAsync.
    /// </summary>
    public Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        return _securityNonceStore.CleanupExpiredAsync(cancellationToken);
    }

    /// <summary>
    /// Delegates to security nonce store's ConsumeNonceIfMatchesAsync.
    /// </summary>
    public Task<bool> ConsumeNonceIfMatchesAsync(string thumbprint, string expectedNonce, CancellationToken cancellationToken = default)
    {
        return _securityNonceStore.ConsumeNonceIfMatchesAsync(thumbprint, expectedNonce, cancellationToken);
    }
}
