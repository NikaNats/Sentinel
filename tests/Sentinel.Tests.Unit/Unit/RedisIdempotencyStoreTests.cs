using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Redis;
using Sentinel.Redis.Stores;
using Sentinel.Security.Abstractions.Idempotency;
using StackExchange.Redis;

namespace Sentinel.Tests.Unit.Unit;

public sealed class RedisIdempotencyStoreTests
{
    private const string RequestKey = "idempotency:user-1:payment-txn-999";
    private readonly Mock<IDatabase> _databaseMock;
    private readonly TimeSpan _inProgressTtl = TimeSpan.FromSeconds(5);
    private readonly Mock<IConnectionMultiplexer> _multiplexerMock;
    private readonly Mock<IRedisConnectionProvider> _providerMock;
    private readonly RedisIdempotencyStore _sut;

    public RedisIdempotencyStoreTests()
    {
        _providerMock = new Mock<IRedisConnectionProvider>(MockBehavior.Strict);
        _multiplexerMock = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        _databaseMock = new Mock<IDatabase>(MockBehavior.Strict);

        _providerMock
            .Setup(x => x.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(_multiplexerMock.Object);

        _multiplexerMock
            .Setup(x => x.GetDatabase(It.IsAny<int>(), It.IsAny<object>()))
            .Returns(_databaseMock.Object);

        _sut = new RedisIdempotencyStore(_providerMock.Object, NullLogger<RedisIdempotencyStore>.Instance);
    }

    [Fact(DisplayName = "✅ RedisIdempotencyStore: Successfully recovers from TOCTOU race and acquires lock on retry")]
    public async Task TryAcquireAsync_WhenKeyExpiresBetweenSetAndGet_RetriesAndSuccessfullyAcquires()
    {
        // Arrange
        _databaseMock
            .SetupSequence(x => x.StringSetAsync(
                RequestKey,
                "IN_PROGRESS",
                _inProgressTtl,
                When.NotExists,
                CommandFlags.None))
            .ReturnsAsync(false)
            .ReturnsAsync(true);

        _databaseMock
            .Setup(x => x.StringGetAsync(RequestKey, CommandFlags.None))
            .ReturnsAsync(RedisValue.Null);

        // Act
        var (state, cachedResponse) = await _sut.TryAcquireAsync(RequestKey, _inProgressTtl, CancellationToken.None);

        // Assert
        state.Should().Be(IdempotencyAcquireResult.Acquired,
            "The store must retry and report Acquired once it successfully writes IN_PROGRESS to Redis on retry.");
        cachedResponse.Should().BeNull();

        _databaseMock.Verify(
            x => x.StringSetAsync(RequestKey, "IN_PROGRESS", _inProgressTtl, When.NotExists, CommandFlags.None),
            Times.Exactly(2));
        _databaseMock.Verify(x => x.StringGetAsync(RequestKey, CommandFlags.None), Times.Once);
    }

    [Fact(DisplayName =
        "✅ RedisIdempotencyStore: Exceeding max retries under extreme contention fails closed to InProgress")]
    public async Task TryAcquireAsync_WhenContentionExhaustsRetries_FailsClosedToInProgress()
    {
        // Arrange
        _databaseMock
            .Setup(x => x.StringSetAsync(
                RequestKey,
                "IN_PROGRESS",
                _inProgressTtl,
                When.NotExists,
                CommandFlags.None))
            .ReturnsAsync(false);

        _databaseMock
            .Setup(x => x.StringGetAsync(RequestKey, CommandFlags.None))
            .ReturnsAsync(RedisValue.Null);

        // Act
        var (state, cachedResponse) = await _sut.TryAcquireAsync(RequestKey, _inProgressTtl, CancellationToken.None);

        // Assert
        state.Should().Be(IdempotencyAcquireResult.InProgress,
            "Under endless lock contention, the store must fail closed to InProgress to prevent double execution.");
        cachedResponse.Should().BeNull();

        _databaseMock.Verify(
            x => x.StringSetAsync(RequestKey, "IN_PROGRESS", _inProgressTtl, When.NotExists, CommandFlags.None),
            Times.Exactly(3));
        _databaseMock.Verify(x => x.StringGetAsync(RequestKey, CommandFlags.None), Times.Exactly(3));
    }

    [Fact(DisplayName = "✅ RedisIdempotencyStore: Replays cached response on Completed state")]
    public async Task TryAcquireAsync_WhenKeyContainsCachedResponse_ReturnsCompletedWithResponse()
    {
        // Arrange
        var cachedResponse = new CachedHttpResponse(200, "application/json", "{\"status\":\"ok\"}"u8.ToArray());
        var json = JsonSerializer.Serialize(cachedResponse, RedisJsonContext.Default.CachedHttpResponse);

        _databaseMock
            .Setup(x => x.StringSetAsync(
                RequestKey,
                "IN_PROGRESS",
                _inProgressTtl,
                When.NotExists,
                CommandFlags.None))
            .ReturnsAsync(false);

        _databaseMock
            .Setup(x => x.StringGetAsync(RequestKey, CommandFlags.None))
            .ReturnsAsync(json);

        // Act
        var (state, response) = await _sut.TryAcquireAsync(RequestKey, _inProgressTtl, CancellationToken.None);

        // Assert
        state.Should().Be(IdempotencyAcquireResult.Completed);
        response.Should().NotBeNull();
        response!.StatusCode.Should().Be(200);
        response.ContentType.Should().Be("application/json");
        response.Body.Should().BeEquivalentTo(cachedResponse.Body);
    }
}
