using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Cache;

namespace Sentinel.Tests.Unit;

public sealed class HybridJtiReplayCacheTests
{
    [Fact]
    public async Task TryStoreIfNotExistsAsync_WhenRedisUnavailableAndFallbackEnabled_UsesNodeLocalMemory()
    {
        var serviceProvider = new Mock<IServiceProvider>();
        serviceProvider
            .Setup(x => x.GetService(typeof(StackExchange.Redis.IConnectionMultiplexer)))
            .Throws(new InvalidOperationException("redis down"));

        using var memoryCache = new MemoryCache(new MemoryCacheOptions());
        var sut = new HybridJtiReplayCache(
            serviceProvider.Object,
            memoryCache,
            Options.Create(new RedisOptions { EnableInMemFallback = true }),
            NullLogger<HybridJtiReplayCache>.Instance);

        var first = await sut.TryStoreIfNotExistsAsync("jti-1", TimeSpan.FromSeconds(60), CancellationToken.None);
        var second = await sut.TryStoreIfNotExistsAsync("jti-1", TimeSpan.FromSeconds(60), CancellationToken.None);

        Assert.True(first);
        Assert.False(second);
    }

    [Fact]
    public async Task TryStoreIfNotExistsAsync_WhenRedisUnavailableAndFallbackDisabled_ThrowsUnavailableException()
    {
        var serviceProvider = new Mock<IServiceProvider>();
        serviceProvider
            .Setup(x => x.GetService(typeof(StackExchange.Redis.IConnectionMultiplexer)))
            .Returns((object?)null);

        using var memoryCache = new MemoryCache(new MemoryCacheOptions());
        var sut = new HybridJtiReplayCache(
            serviceProvider.Object,
            memoryCache,
            Options.Create(new RedisOptions { EnableInMemFallback = false }),
            NullLogger<HybridJtiReplayCache>.Instance);

        await Assert.ThrowsAsync<ReplayCacheUnavailableException>(() =>
            sut.TryStoreIfNotExistsAsync("jti-1", TimeSpan.FromSeconds(60), CancellationToken.None));
    }
}
