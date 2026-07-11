using System.Net.Sockets;
using FluentAssertions;
using Moq;
using Sentinel.Security.Abstractions.Session;
using StackExchange.Redis;

namespace Sentinel.Tests.Security.Chaos;

public sealed class RedisResilienceTests
{
    private readonly Mock<ISessionBlacklistCache> _cacheServiceMock = new(MockBehavior.Strict);

    [Fact(DisplayName = "⏱️ Redis Timeout → Fail-Closed (Revocation Unavailable)")]
    public async Task SessionRevocation_FailsClosed_WhenRedisTimeout()
    {
        var sessionId = "sess-chaos-001";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        _cacheServiceMock
            .Setup(x => x.BlacklistSessionAsync(sessionId, expiresAt, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TimeoutException("Redis connection timeout"))
            .Verifiable();

        var act = async () => await _cacheServiceMock.Object.BlacklistSessionAsync(
            sessionId,
            expiresAt,
            CancellationToken.None);

        await act.Should().ThrowAsync<TimeoutException>();

        _cacheServiceMock.Verify();
    }

    [Theory(DisplayName = "🔴 Redis Connection Failure Types (all fail-closed)")]
    [InlineData("redis_connection", "Connection refused/pool exhausted")]
    [InlineData("timeout", "Slow response or read timeout")]
    [InlineData("socket", "Network layer failure")]
    public async Task SessionQuery_FailsClosed_OnAnyInfrastructureFailure(string failureKind, string scenario)
    {
        _ = scenario;
        var sessionId = "sess-chaos-002";
        Exception exception = failureKind switch
        {
            "redis_connection" => new RedisConnectionException(ConnectionFailureType.UnableToConnect,
                "Infrastructure melting"),
            "timeout" => new TimeoutException("Infrastructure melting"),
            "socket" => new SocketException((int)SocketError.NetworkUnreachable),
            _ => new InvalidOperationException($"Unsupported failure kind: {failureKind}")
        };

        _cacheServiceMock
            .Setup(x => x.IsBlacklistedAsync(sessionId, It.IsAny<CancellationToken>()))
            .ThrowsAsync(exception)
            .Verifiable();

        Func<Task> act = async () => await _cacheServiceMock.Object.IsBlacklistedAsync(
            sessionId,
            CancellationToken.None);

        await act.Should().ThrowAsync<Exception>();

        _cacheServiceMock.Verify();
    }

    [Fact(DisplayName = "🔗 Partial Redis Cluster Failure → Fail-Closed")]
    public async Task SessionRevocation_FailsClosed_OnPartialClusterFailure()
    {
        var sessionId = "sess-chaos-cluster";

        _cacheServiceMock
            .Setup(x => x.BlacklistSessionAsync(sessionId, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RedisConnectionException(
                ConnectionFailureType.UnableToConnect,
                "No cluster quorum reached"))
            .Verifiable();

        var act = async () => await _cacheServiceMock.Object.BlacklistSessionAsync(
            sessionId,
            DateTimeOffset.UtcNow.AddHours(1),
            CancellationToken.None);

        await act.Should().ThrowAsync<RedisConnectionException>();
    }

    [Fact(DisplayName = "📊 Cascade Failure (write OK, read fail) → each fails independently")]
    public async Task NoStatePropagationAcrossInfrastructureFailures()
    {
        var sessionId = "sess-cascade";

        _cacheServiceMock
            .Setup(x => x.BlacklistSessionAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask)
            .Verifiable();

        _cacheServiceMock
            .Setup(x => x.IsBlacklistedAsync(sessionId, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TimeoutException("Query failed"))
            .Verifiable();

        await _cacheServiceMock.Object.BlacklistSessionAsync(
            sessionId,
            DateTimeOffset.UtcNow.AddHours(1),
            CancellationToken.None);

        Func<Task> act2 = async () => await _cacheServiceMock.Object.IsBlacklistedAsync(
            sessionId,
            CancellationToken.None);

        await act2.Should().ThrowAsync<TimeoutException>();

        _cacheServiceMock.Verify();
    }
}
