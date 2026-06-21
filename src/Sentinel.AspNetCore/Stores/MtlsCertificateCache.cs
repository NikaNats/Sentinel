using Microsoft.Extensions.Caching.Memory;

namespace Sentinel.AspNetCore.Stores;

/// <summary>
///     2026 Enterprise Standard: Isolated, Bounded Memory Cache for mTLS thumbprints.
///     Protects against L7 Denial of Service (OOM) attacks by enforcing strict capacity limits
///     and preventing "Noisy Neighbor" cache eviction in the global IMemoryCache.
/// </summary>
public sealed class MtlsCertificateCache : IDisposable
{
    private readonly MemoryCache _cache;

    public MtlsCertificateCache() : this(10_000)
    {
    }

    internal MtlsCertificateCache(int sizeLimit)
    {
        _cache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = sizeLimit,
            CompactionPercentage = 0.20
        });
    }

    public int Count => _cache.Count;

    public void Dispose() => _cache.Dispose();

    public bool TryGetValue(string key, out string? thumbprint) => _cache.TryGetValue(key, out thumbprint);

    public void Set(string key, string thumbprint, TimeSpan expiration)
    {
        var options = new MemoryCacheEntryOptions()
            .SetSlidingExpiration(expiration)
            .SetSize(1);

        _cache.Set(key, thumbprint, options);
    }
}
