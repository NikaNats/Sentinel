using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Cache;

namespace Sentinel.Tests.Unit;

public sealed class JtiReplayCacheTests
{
    [Fact]
    public async Task ExistsAsync_WhenRedisThrows_ThrowsReplayCacheUnavailableException()
    {
        var distributedCache = new Mock<IDistributedCache>();
        distributedCache
            .Setup(x => x.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Redis connection refused"));

        var sut = new JtiReplayCache(distributedCache.Object, NullLogger<JtiReplayCache>.Instance);

        var ex = await Assert.ThrowsAsync<ReplayCacheUnavailableException>(() =>
            sut.ExistsAsync("jti-12345", CancellationToken.None).AsTask());

        Assert.Contains("jti replay cache unavailable", ex.Message);
    }

    [Fact]
    public async Task StoreAsync_WithTtl_WritesKeyToCache()
    {
        var distributedCache = new Mock<IDistributedCache>();
        var sut = new JtiReplayCache(distributedCache.Object, NullLogger<JtiReplayCache>.Instance);

        await sut.StoreAsync("jti-abc", TimeSpan.FromSeconds(30), CancellationToken.None);

        distributedCache.Verify(x =>
            x.SetAsync(
                It.Is<string>(k => k == "replay:jti:jti-abc"),
                It.IsAny<byte[]>(),
                It.Is<DistributedCacheEntryOptions>(o => o.AbsoluteExpirationRelativeToNow == TimeSpan.FromSeconds(30)),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }
}
