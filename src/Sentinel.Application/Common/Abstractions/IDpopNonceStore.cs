namespace Sentinel.Application.Common.Abstractions;

public interface IDpopNonceStore
{
    Task<string?> GetNonceAsync(string thumbprint, CancellationToken ct);
    Task<bool> TryStoreNonceAsync(string thumbprint, string nonce, TimeSpan ttl, CancellationToken ct);
    Task<bool> ConsumeNonceIfMatchesAsync(string thumbprint, string expectedNonce, CancellationToken ct);
}
