using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Cache;
using StackExchange.Redis;

namespace Sentinel.Tests.Unit;

public sealed class JtiReplayCacheTests
{
    [Fact]
    public async Task TryStoreIfNotExistsAsync_WhenRedisThrows_ThrowsReplayCacheUnavailableException()
    {
        var db = new Mock<IDatabase>();
        db.Setup(x => x.StringSetAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(), It.IsAny<When>()))
            .ThrowsAsync(new Exception("Redis connection refused"));

        var redis = new Mock<IConnectionMultiplexer>();
        redis.Setup(x => x.GetDatabase(It.IsAny<int>(), It.IsAny<object?>()))
            .Returns(db.Object);

        var sut = new JtiReplayCache(redis.Object, NullLogger<JtiReplayCache>.Instance);

        var ex = await Assert.ThrowsAsync<ReplayCacheUnavailableException>(() =>
            sut.TryStoreIfNotExistsAsync("jti-12345", TimeSpan.FromSeconds(30), CancellationToken.None));

        Assert.Contains("jti replay cache unavailable", ex.Message);
    }

    [Fact]
    public async Task TryStoreIfNotExistsAsync_WithTtl_UsesSetNxAndReturnsStoredState()
    {
        var db = new Mock<IDatabase>();
        db.Setup(x => x.StringSetAsync(
                It.Is<RedisKey>(k => k.ToString() == "replay:jti:jti-abc"),
                RedisValue.EmptyString,
                TimeSpan.FromSeconds(30),
            When.NotExists))
            .ReturnsAsync(true);

        var redis = new Mock<IConnectionMultiplexer>();
        redis.Setup(x => x.GetDatabase(It.IsAny<int>(), It.IsAny<object?>()))
            .Returns(db.Object);

        var sut = new JtiReplayCache(redis.Object, NullLogger<JtiReplayCache>.Instance);

        var stored = await sut.TryStoreIfNotExistsAsync("jti-abc", TimeSpan.FromSeconds(30), CancellationToken.None);

        Assert.True(stored);
    }
}
