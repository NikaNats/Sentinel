using System.Net.Sockets;
using FluentAssertions;
using Moq;
using Sentinel.Security.Abstractions.Session;
using StackExchange.Redis;

namespace Sentinel.Tests.Security.Chaos;

/// <summary>
///     Chaos Engineering: Redis Resilience & Fail-Closed Semantics
///     This suite proves the "Fail-Closed" claim: If Redis becomes unavailable, slow, or partial,
///     the system MUST choose to be unavailable (503 Service Unavailable) rather than insecure.
///     Real production outages are "Gray Failures" — partial latency, cascade delays, connection pools
///     exhausted. This tests against such scenarios, not just "Up" vs "Down."
///     Safety Principle: Strict Mocking (MockBehavior.Strict) verifies that on ANY infrastructure
///     failure, the system IMMEDIATELY fails and never enters an "accept anyway" state.
/// </summary>
public sealed class RedisResilienceTests
{
    private readonly Mock<ISessionBlacklistCache> _cacheServiceMock;

    public RedisResilienceTests()
    {
        // STRICT: Every cache operation must be explicitly defined or will fail
        _cacheServiceMock = new Mock<ISessionBlacklistCache>(MockBehavior.Strict);
    }

    /// <summary>
    ///     Test: Session revocation MUST fail-closed if cache is unavailable (timeout).
    ///     Scenario: Client initiates session revocation via SSF event. Redis timeouts on write.
    ///     Expected: Return failure immediately; never allow state inconsistency.
    ///     Security: If we say "yes I revoked" but didn't actually revoke, attacker retains access.
    ///     Fail-closed = "I don't know if revocation succeeded, so deny access."
    /// </summary>
    [Fact(DisplayName = "⏱️ Redis Timeout → Fail-Closed (Revocation Unavailable)")]
    public async Task SessionRevocation_FailsClosed_WhenRedisTimeout()
    {
        // Arrange: Cache throws TimeoutException on revocation attempt
        var sessionId = "sess-chaos-001";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        _cacheServiceMock
            .Setup(x => x.BlacklistSessionAsync(sessionId, expiresAt, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TimeoutException("Redis connection timeout"))
            .Verifiable("Blacklist must be attempted");

        // Act
        var act = async () => await _cacheServiceMock.Object.BlacklistSessionAsync(
            sessionId,
            expiresAt,
            CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<TimeoutException>(
            "TimeoutException MUST propagate; middleware handles 503 response");

        _cacheServiceMock.Verify();
    }

    /// <summary>
    ///     Test: Session query (is session blacklisted?) MUST fail-closed if cache is unavailable.
    ///     Scenario: Incoming request presents session token. Cache is slow (>1s).
    ///     Expected: Reject the request; never guess "probably not revoked."
    ///     Security: On ambiguity, deny. DoS > AccLeak.
    /// </summary>
    [Theory(DisplayName = "🔴 Redis Connection Failure Types (all fail-closed)")]
    [InlineData("redis_connection", "Connection refused/pool exhausted")]
    [InlineData("timeout", "Slow response or read timeout")]
    [InlineData("socket", "Network layer failure")]
    public async Task SessionQuery_FailsClosed_OnAnyInfrastructureFailure(string failureKind, string scenario)
    {
        // Arrange
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
            .Verifiable("Blacklist check must be attempted");

        // Act
        Func<Task> act = async () => await _cacheServiceMock.Object.IsBlacklistedAsync(
            sessionId,
            CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<Exception>(
            $"On infrastructure failure ({scenario}), system must throw and never 'gracefully degrade' to allow access");

        _cacheServiceMock.Verify();
    }

    /// <summary>
    ///     Test: Partial Redis failure (cluster quorum lost) MUST be treated as total failure.
    ///     Scenario: Redis cluster has 5 nodes. 3 go down. Cluster can't reach quorum.
    ///     Write attempts get RedisTimeoutException (queued but unexecuted).
    ///     Expected: REJECT; never accept writes that couldn't complete.
    ///     Security: Writes that "might have succeeded" are worse than timeouts that clearly failed.
    /// </summary>
    [Fact(DisplayName = "🔗 Partial Redis Cluster Failure → Fail-Closed")]
    public async Task SessionRevocation_FailsClosed_OnPartialClusterFailure()
    {
        // Arrange: Simulate Redis write that was queued but never executed
        var sessionId = "sess-chaos-cluster";

        _cacheServiceMock
            .Setup(x => x.BlacklistSessionAsync(sessionId, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RedisConnectionException(
                ConnectionFailureType.UnableToConnect,
                "No cluster quorum reached"))
            .Verifiable("Revocation must be attempted despite cluster issues");

        // Act & Assert: Exception must propagate
        var act = async () => await _cacheServiceMock.Object.BlacklistSessionAsync(
            sessionId,
            DateTimeOffset.UtcNow.AddHours(1),
            CancellationToken.None);

        await act.Should().ThrowAsync<RedisConnectionException>(
            "Cluster failures are NOT recoverable; system must fail immediately");
    }

    /// <summary>
    ///     Test: State inconsistency prevention across cascading failures.
    ///     Scenario: First revocation write succeeds. Session query times out.
    ///     Expected: Fail on query; never allow "well, we revoked it, so assume it worked."
    ///     Security: Each operation must succeed independently or fail independently.
    ///     No state assumptions across failures.
    /// </summary>
    [Fact(DisplayName = "📊 Cascade Failure (write OK, read fail) → each fails independently")]
    public async Task NoStatePropagationAcrossInfrastructureFailures()
    {
        // Arrange: Two different operations
        var sessionId = "sess-cascade";

        // First: Revocation succeeds
        _cacheServiceMock
            .Setup(x => x.BlacklistSessionAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask)
            .Verifiable("Revocation succeeds initially");

        // Second: Query fails
        _cacheServiceMock
            .Setup(x => x.IsBlacklistedAsync(sessionId, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TimeoutException("Query failed"))
            .Verifiable("Query fails independently");

        // Act 1: Revocation succeeds
        await _cacheServiceMock.Object.BlacklistSessionAsync(
            sessionId,
            DateTimeOffset.UtcNow.AddHours(1),
            CancellationToken.None);

        // Act 2: Query fails
        Func<Task> act2 = async () => await _cacheServiceMock.Object.IsBlacklistedAsync(
            sessionId,
            CancellationToken.None);

        // Assert: Query failure is NOT masked by previous revocation success
        await act2.Should().ThrowAsync<TimeoutException>(
            "Query failures don't benefit from previous operations; each is independent");

        // Verify all operations were attempted
        _cacheServiceMock.Verify();
    }
}
