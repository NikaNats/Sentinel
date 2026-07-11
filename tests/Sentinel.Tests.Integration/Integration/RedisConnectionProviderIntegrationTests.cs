using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Redis;
using StackExchange.Redis;
using Testcontainers.Redis;

namespace Sentinel.Tests.Integration.Integration;

public sealed class RedisConnectionProviderIntegrationTests : IAsyncLifetime
{
    private readonly RedisContainer _redisContainer = new RedisBuilder("redis:7.4-alpine").Build();
    private string _connectionString = string.Empty;
    private RedisConnectionProvider _sut = null!;

    private static CancellationToken TestCancellationToken => TestContext.Current.CancellationToken;

    public async ValueTask InitializeAsync()
    {
        await _redisContainer.StartAsync(TestCancellationToken);
        _connectionString = _redisContainer.GetConnectionString();

        var options = new RedisOptions
        {
            EndPoint = _connectionString,
            SyncTimeout = 3000
        };

        _sut = new RedisConnectionProvider(options, NullLogger<RedisConnectionProvider>.Instance);
    }

    public async ValueTask DisposeAsync()
    {
        await _sut.DisposeAsync();
        await _redisContainer.DisposeAsync();
    }

    [Fact(DisplayName =
        "🔐 Integration: KEYS command is strictly blocked on live Redis and throws RedisCommandException")]
    public async Task GetConnectionAsync_WhenExecutingBlockedCommand_ThrowsRedisCommandException()
    {
        // Arrange
        var connection = await _sut.GetConnectionAsync(TestCancellationToken);
        var db = connection.GetDatabase();

        await db.StringSetAsync("test_key", "test_value");

        // Act
        var act = async () => await db.ExecuteAsync("KEYS", "*");

        // Assert
        await act.Should().ThrowAsync<RedisCommandException>()
            .WithMessage("*disabled*")
            .WithMessage("*KEYS*");
    }
}
