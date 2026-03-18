using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.Infrastructure.Cache;

namespace Sentinel.Tests.Unit;

public sealed class HybridNonceStoreTests
{
    [Fact]
    public async Task NonceLifecycle_WhenRedisUnavailable_UsesNodeLocalFallback()
    {
        var serviceProvider = new Mock<IServiceProvider>();
        serviceProvider
            .Setup(x => x.GetService(typeof(StackExchange.Redis.IConnectionMultiplexer)))
            .Throws(new InvalidOperationException("redis down"));

        using var memoryCache = new MemoryCache(new MemoryCacheOptions());
        var sut = new HybridNonceStore(
            serviceProvider.Object,
            memoryCache,
            Options.Create(new RedisOptions { EnableInMemFallback = true }),
            NullLogger<HybridNonceStore>.Instance);

        var stored = await sut.TryStoreNonceAsync("thumbprint-1", "nonce-1", TimeSpan.FromMinutes(5), CancellationToken.None);
        var nonce = await sut.GetNonceAsync("thumbprint-1", CancellationToken.None);
        var consumed = await sut.ConsumeNonceIfMatchesAsync("thumbprint-1", "nonce-1", CancellationToken.None);
        var nonceAfter = await sut.GetNonceAsync("thumbprint-1", CancellationToken.None);

        Assert.True(stored);
        Assert.Equal("nonce-1", nonce);
        Assert.True(consumed);
        Assert.Null(nonceAfter);
    }
}
