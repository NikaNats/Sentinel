using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Redis;
using Sentinel.Redis.Stores;
using StackExchange.Redis;
using FluentAssertions;

namespace Sentinel.Tests.Unit;

public sealed class RedisJtiReplayCacheTests
{
    [Fact]
    public async Task TryMarkUsedAsync_WhenRedisThrows_FallsBackToInMemoryCache()
    {
        // Arrange
        var providerMock = new Mock<IRedisConnectionProvider>();

        // Force the provider to throw a Redis connection exception
        providerMock
            .Setup(x => x.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "Simulated outage"));

        var options = new RedisOptions { KeyPrefix = "test:", EnableInMemoryFallback = true };
        var sut = new RedisJtiReplayCache(providerMock.Object, options, NullLogger<RedisJtiReplayCache>.Instance);

        var jti = Guid.NewGuid().ToString();
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        // Act - First call should succeed using in-memory fallback
        var firstResult = await sut.TryMarkUsedAsync(jti, expiresAt);

        // Act - Second call should fail (replay detected by fallback)
        var secondResult = await sut.TryMarkUsedAsync(jti, expiresAt);

        // Assert
        firstResult.Should().BeTrue("First JTI should be marked successfully");
        secondResult.Should().BeFalse("Second JTI should be rejected as replay");
    }

    [Fact]
    public async Task TryMarkUsedAsync_WhenRedisConnectionTimeoutThrows_FallsBackToInMemory()
    {
        // Arrange
        var providerMock = new Mock<IRedisConnectionProvider>();

        providerMock
            .Setup(x => x.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TimeoutException("Connection timeout"));

        var options = new RedisOptions { KeyPrefix = "test:", EnableInMemoryFallback = true };
        var sut = new RedisJtiReplayCache(providerMock.Object, options, NullLogger<RedisJtiReplayCache>.Instance);

        var jti = Guid.NewGuid().ToString();
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        // Act
        var result = await sut.TryMarkUsedAsync(jti, expiresAt);

        // Assert
        result.Should().BeTrue("Should successfully fallback to in-memory cache");
    }

    [Fact]
    public async Task TryMarkUsedAsync_WhenNoFallbackEnabled_ThrowsReplayCacheUnavailableException()
    {
        // Arrange
        var providerMock = new Mock<IRedisConnectionProvider>();

        providerMock
            .Setup(x => x.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "Outage"));

        var options = new RedisOptions { KeyPrefix = "test:", EnableInMemoryFallback = false };
        var sut = new RedisJtiReplayCache(providerMock.Object, options, NullLogger<RedisJtiReplayCache>.Instance);

        var jti = Guid.NewGuid().ToString();
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        // Act & Assert
        await Assert.ThrowsAsync<ReplayCacheUnavailableException>(
            () => sut.TryMarkUsedAsync(jti, expiresAt));
    }

    [Fact]
    public async Task TryMarkUsedAsync_WithNullJti_ThrowsArgumentException()
    {
        // Arrange
        var providerMock = new Mock<IRedisConnectionProvider>();
        var options = new RedisOptions { KeyPrefix = "test:" };
        var sut = new RedisJtiReplayCache(providerMock.Object, options, NullLogger<RedisJtiReplayCache>.Instance);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(
            () => sut.TryMarkUsedAsync(null!, DateTimeOffset.UtcNow.AddMinutes(5)));
    }

    [Fact]
    public async Task TryMarkUsedAsync_WithEmptyJti_ThrowsArgumentException()
    {
        // Arrange
        var providerMock = new Mock<IRedisConnectionProvider>();
        var options = new RedisOptions { KeyPrefix = "test:" };
        var sut = new RedisJtiReplayCache(providerMock.Object, options, NullLogger<RedisJtiReplayCache>.Instance);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(
            () => sut.TryMarkUsedAsync("", DateTimeOffset.UtcNow.AddMinutes(5)));
    }

    [Fact]
    public async Task TryMarkUsedAsync_WithRedisGenericException_FallsBackIfEnabled()
    {
        // Arrange
        var providerMock = new Mock<IRedisConnectionProvider>();

        providerMock
            .Setup(x => x.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Some unexpected error"));

        var options = new RedisOptions { KeyPrefix = "test:", EnableInMemoryFallback = true };
        var sut = new RedisJtiReplayCache(providerMock.Object, options, NullLogger<RedisJtiReplayCache>.Instance);

        var jti = Guid.NewGuid().ToString();
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        // Act
        var result = await sut.TryMarkUsedAsync(jti, expiresAt);

        // Assert
        result.Should().BeTrue("Should fallback to in-memory cache on generic exception");
    }

    [Fact]
    public async Task TryMarkUsedAsync_MultipleDistinctJtis_AllSucceedViaFallback()
    {
        // Arrange
        var providerMock = new Mock<IRedisConnectionProvider>();
        providerMock
            .Setup(x => x.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "Down"));

        var options = new RedisOptions { KeyPrefix = "test:", EnableInMemoryFallback = true };
        var sut = new RedisJtiReplayCache(providerMock.Object, options, NullLogger<RedisJtiReplayCache>.Instance);

        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);
        var jti1 = Guid.NewGuid().ToString();
        var jti2 = Guid.NewGuid().ToString();

        // Act
        var result1 = await sut.TryMarkUsedAsync(jti1, expiresAt);
        var result2 = await sut.TryMarkUsedAsync(jti2, expiresAt);

        // Assert
        result1.Should().BeTrue();
        result2.Should().BeTrue();
    }

    [Fact]
    public async Task TryMarkUsedAsync_SamJtiTwice_SecondFails()
    {
        // Arrange
        var providerMock = new Mock<IRedisConnectionProvider>();
        providerMock
            .Setup(x => x.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "Down"));

        var options = new RedisOptions { KeyPrefix = "test:", EnableInMemoryFallback = true };
        var sut = new RedisJtiReplayCache(providerMock.Object, options, NullLogger<RedisJtiReplayCache>.Instance);

        var jti = Guid.NewGuid().ToString();
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        // Act
        var result1 = await sut.TryMarkUsedAsync(jti, expiresAt);
        var result2 = await sut.TryMarkUsedAsync(jti, expiresAt);

        // Assert
        result1.Should().BeTrue("First use should succeed");
        result2.Should().BeFalse("Replay should be detected");
    }
}
