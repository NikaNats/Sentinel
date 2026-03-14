namespace Sentinel.Application.Common.Abstractions;

public interface IDpopNonceStore
{
    Task<string?> ConsumeNonceAsync(string thumbprint, CancellationToken ct);
    Task StoreNonceAsync(string thumbprint, string nonce, TimeSpan ttl, CancellationToken ct);
}
