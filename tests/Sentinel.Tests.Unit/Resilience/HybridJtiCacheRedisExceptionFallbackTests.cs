using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.Infrastructure.Cache;
using StackExchange.Redis;

namespace Sentinel.Tests.Resilience;

public sealed class HybridJtiCacheRedisExceptionFallbackTests
{
    [Fact]
    public async Task TryStoreIfNotExistsAsync_WhenRedisThrowsRedisConnectionException_FallsBackToMemory()
    {
        var multiplexer = new Mock<IConnectionMultiplexer>();
        multiplexer.SetupGet(x => x.IsConnected).Returns(true);
        multiplexer
            .Setup(x => x.GetDatabase(It.IsAny<int>(), It.IsAny<object?>()))
            .Throws(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "redis unavailable"));

        var provider = new Mock<IServiceProvider>();
        provider.Setup(x => x.GetService(typeof(IConnectionMultiplexer))).Returns(multiplexer.Object);

        using var memoryCache = new MemoryCache(new MemoryCacheOptions());
        var sut = new HybridJtiReplayCache(
            provider.Object,
            memoryCache,
            Options.Create(new RedisOptions { EnableInMemFallback = true }),
            NullLogger<HybridJtiReplayCache>.Instance);

        var first = await sut.TryStoreIfNotExistsAsync("jti-fallback", TimeSpan.FromSeconds(30),
            CancellationToken.None);
        var second =
            await sut.TryStoreIfNotExistsAsync("jti-fallback", TimeSpan.FromSeconds(30), CancellationToken.None);

        first.Should().BeTrue();
        second.Should().BeFalse();
    }
}
