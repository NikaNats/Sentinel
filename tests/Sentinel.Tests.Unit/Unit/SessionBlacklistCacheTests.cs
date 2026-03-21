using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Cache;
using StackExchange.Redis;

namespace Sentinel.Tests.Unit;

public sealed class SessionBlacklistCacheTests
{
    [Fact]
    public async Task BlacklistSessionAsync_WhenStored_IsReportedAsBlacklisted()
    {
        var db = new Mock<IDatabase>();
        db.Setup(x => x.StringSetAsync("blacklist:sid:sid-1", RedisValue.EmptyString, It.IsAny<TimeSpan?>(),
                When.Always, CommandFlags.None))
            .ReturnsAsync(true);
        db.Setup(x => x.KeyExistsAsync("blacklist:sid:sid-1", CommandFlags.None))
            .ReturnsAsync(true);

        var redis = new Mock<IConnectionMultiplexer>();
        redis.Setup(x => x.GetDatabase(It.IsAny<int>(), It.IsAny<object?>())).Returns(db.Object);

        var sut = new SessionBlacklistCache(redis.Object, NullLogger<SessionBlacklistCache>.Instance);

        await sut.BlacklistSessionAsync("sid-1", TimeSpan.FromMinutes(5), CancellationToken.None);
        var result = await sut.IsSessionBlacklistedAsync("sid-1", CancellationToken.None);

        Assert.True(result);
        db.Verify(
            x => x.StringSetAsync("blacklist:sid:sid-1", RedisValue.EmptyString, It.IsAny<TimeSpan?>(), When.Always,
                CommandFlags.None), Times.Once);
    }

    [Fact]
    public async Task IsSessionBlacklistedAsync_WhenCacheThrows_ThrowsReplayCacheUnavailableException()
    {
        var db = new Mock<IDatabase>();
        db.Setup(x => x.KeyExistsAsync(It.IsAny<RedisKey>(), CommandFlags.None))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "redis down"));

        var redis = new Mock<IConnectionMultiplexer>();
        redis.Setup(x => x.GetDatabase(It.IsAny<int>(), It.IsAny<object?>())).Returns(db.Object);

        var sut = new SessionBlacklistCache(redis.Object, NullLogger<SessionBlacklistCache>.Instance);

        await Assert.ThrowsAsync<ReplayCacheUnavailableException>(async () =>
            await sut.IsSessionBlacklistedAsync("sid-1", CancellationToken.None));
    }
}
