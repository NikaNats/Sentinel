using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Infrastructure.Cache;

namespace Sentinel.Tests.Unit;

public sealed class SessionBlacklistCacheTests
{
    [Fact]
    public async Task BlacklistSessionAsync_WhenStored_IsReportedAsBlacklisted()
    {
        var cache = new Mock<IDistributedCache>();
        cache.Setup(x => x.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync([1]);

        var sut = new SessionBlacklistCache(cache.Object, NullLogger<SessionBlacklistCache>.Instance);

        await sut.BlacklistSessionAsync("sid-1", TimeSpan.FromMinutes(5), CancellationToken.None);
        var result = await sut.IsSessionBlacklistedAsync("sid-1", CancellationToken.None);

        Assert.True(result);
        cache.Verify(x => x.SetAsync("blacklist:sid:sid-1", It.IsAny<byte[]>(), It.IsAny<DistributedCacheEntryOptions>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task IsSessionBlacklistedAsync_WhenCacheThrows_ThrowsReplayCacheUnavailableException()
    {
        var cache = new Mock<IDistributedCache>();
        cache.Setup(x => x.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("redis down"));

        var sut = new SessionBlacklistCache(cache.Object, NullLogger<SessionBlacklistCache>.Instance);

        await Assert.ThrowsAsync<ReplayCacheUnavailableException>(async () =>
            await sut.IsSessionBlacklistedAsync("sid-1", CancellationToken.None));
    }
}
