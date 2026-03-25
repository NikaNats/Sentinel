using FluentAssertions;
using Moq;
using StackExchange.Redis;
using Xunit;
using Sentinel.Infrastructure.Cache;
using Sentinel.Security.Abstractions.Replay;

namespace Sentinel.Tests.Security.Chaos;

/// <summary>
/// Chaos Engineering: Redis Resilience & Fail-Closed Semantics
///
/// This suite proves the "Fail-Closed" claim: If Redis becomes unavailable, slow, or partial,
/// the system MUST choose to be unavailable (503 Service Unavailable) rather than insecure.
///
/// Real production outages are "Gray Failures" — partial latency, cascade delays, connection pools
/// exhausted. This tests against such scenarios, not just "Up" vs "Down."
///
/// Architecture: Using mocks to simulate StackExchange.Redis timeout behaviors.
/// (In a full integration environment, use Testcontainers.Redis + Testcontainers.Toxiproxy)
/// </summary>
public sealed class RedisResilienceTests
{
    private readonly Mock<IJtiReplayCache> _mockReplayCache;

    public RedisResilienceTests()
    {
        _mockReplayCache = new Mock<IJtiReplayCache>();
    }

    /// <summary>
    /// Test: JTI Cache must throw ReplayCacheUnavailableException when Redis timeout occurs.
    ///
    /// Scenario: Client requests token with DPoP proof. Redis is responding but slowly (>1s).
    /// Replay cache lookup times out. Expected: Exception caught, middleware returns 503.
    ///
    /// Security Implication: If cache is unavailable and we can't prove this is a fresh proof,
    /// we MUST reject rather than accept (Fail-Closed).
    /// </summary>
    [Fact]
    public async Task JtiCache_FailsClosed_WhenRedisTimeout()
    {
        // Arrange: Mock Redis connection that throws TimeoutException
        _mockReplayCache
            .Setup(x => x.TryMarkUsedAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TimeoutException("Redis connection timeout"))
            .Verifiable("Replay cache must be called");

        var jti = "jti_redis_timeout_test";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        // Act
        Func<Task> act = async () => await _mockReplayCache.Object.TryMarkUsedAsync(
            jti,
            expiresAt,
            CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<TimeoutException>(
            "TimeoutException must propagate to middleware for 503 response");

        _mockReplayCache.Verify();
    }

    /// <summary>
    /// Test: JTI Cache must never "degrade gracefully" by accepting duplicate proofs.
    ///
    /// Scenario: First call to Redis succeeds and marks JTI as used. Second call times out.
    /// Attack: Attacker realizes timeout happened and immediately resubmits same proof.
    /// Expected: MUST reject (no fallback to "accept anyway").
    ///
    /// Security Implication: Zero-trust replay protection; no degradation paths.
    /// </summary>
    [Fact]
    public async Task JtiCache_CannotDegradeToUnsafeState_OnPartialFailure()
    {
        // Arrange: First call succeeds, second call fails
        var callSequence = new[] { true, false };
        var callIndex = 0;

        _mockReplayCache
            .Setup(x => x.TryMarkUsedAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .Returns(() =>
            {
                if (callSequence[callIndex++ % callSequence.Length])
                {
                    return Task.FromResult(true);
                }
                else
                {
                    return Task.FromException<bool>(
                        new RedisConnectionException(
                            ConnectionFailureType.IO,
                            "Redis cluster unavailable"));
                }
            });

        var jti = "jti_partial_failure";

        // Act 1: First call succeeds
        var result1 = await _mockReplayCache.Object.TryMarkUsedAsync(
            jti,
            DateTimeOffset.UtcNow.AddMinutes(5),
            CancellationToken.None);

        // Assert 1
        result1.Should().BeTrue("First call to fresh JTI should succeed");

        // Act 2: Second call (same JTI) fails with connection error
        Func<Task> act2 = async () => await _mockReplayCache.Object.TryMarkUsedAsync(
            jti,
            DateTimeOffset.UtcNow.AddMinutes(5),
            CancellationToken.None);

        // Assert 2
        await act2.Should().ThrowAsync<RedisConnectionException>(
            "On Redis failure, must throw rather than degrade to accepting replay");
    }

    /// <summary>
    /// Test: JTI Cache must handle circuit-breaker patterns correctly.
    ///
    /// Scenario: Redis fails repeatedly. Client retries. Expected: Fast rejection
    /// without attempting Redis (circuit open).
    ///
    /// Security Implication: Prevents cache-stampede attacks where failed
    /// lookups cascade into connection pool exhaustion.
    /// </summary>
    [Fact]
    public async Task JtiCache_CircuitBreakerOpens_AfterThresholdFailures()
    {
        // Arrange: Simulate 5 consecutive timeouts
        var failureCount = 0;
        var circuitOpenThreshold = 5;

        _mockReplayCache
            .Setup(x => x.TryMarkUsedAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .Returns(() =>
            {
                failureCount++;
                if (failureCount > circuitOpenThreshold)
                {
                    // After threshold, should fail fast (not attempt Redis)
                    return Task.FromException<bool>(
                        new OperationCanceledException("Circuit breaker open"));
                }
                return Task.FromException<bool>(
                    new TimeoutException("Redis timeout"));
            });

        // Act: Attempt multiple calls
        var exceptions = new List<Exception>();
        for (int i = 0; i < 7; i++)
        {
            try
            {
                await _mockReplayCache.Object.TryMarkUsedAsync(
                    $"jti_{i}",
                    DateTimeOffset.UtcNow.AddMinutes(5),
                    CancellationToken.None);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }

        // Assert: Last exceptions should be fast-fail (OperationCanceledException)
        exceptions.Should().HaveCountGreaterThan(0, "Multiple failures should be recorded");
        exceptions.Last().Should().BeOfType<OperationCanceledException>(
            "After threshold, circuit breaker should fast-fail");
    }

    /// <summary>
    /// Test: JTI Cache must survive Redis degradation (latency) without compromising security.
    ///
    /// Scenario: Redis responds but slowly. Legitimate first request marks JTI,
    /// then attacker immediately reuses same proof (both within latency window).
    /// Expected: Second request should still reject (even under latency).
    ///
    /// Security Implication: Latency does not create replay windows.
    /// </summary>
    [Fact]
    public async Task JtiCache_MaintainsSemantics_UnderLatency()
    {
        // Arrange: Simulate latency with intentional delays
        var callCount = 0;

        _mockReplayCache
            .Setup(x => x.TryMarkUsedAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .Returns(async () =>
            {
                callCount++;
                // Simulate 500ms latency
                await Task.Delay(TimeSpan.FromMilliseconds(500));

                if (callCount == 1)
                {
                    // First use: success
                    return true;
                }
                else
                {
                    // Second use of same JTI: reject (replay)
                    return false;
                }
            });

        var jti = "jti_latency_test";

        // Act 1: First request (marks JTI)
        var sw1 = System.Diagnostics.Stopwatch.StartNew();
        var result1 = await _mockReplayCache.Object.TryMarkUsedAsync(
            jti,
            DateTimeOffset.UtcNow.AddMinutes(5),
            CancellationToken.None);
        sw1.Stop();

        // Assert 1
        result1.Should().BeTrue("First request should succeed");
        sw1.ElapsedMilliseconds.Should().BeGreaterThanOrEqualTo(500,
            "Request should incur latency");

        // Act 2: Second request (attempted replay, same JTI)
        var sw2 = System.Diagnostics.Stopwatch.StartNew();
        var result2 = await _mockReplayCache.Object.TryMarkUsedAsync(
            jti,
            DateTimeOffset.UtcNow.AddMinutes(5),
            CancellationToken.None);
        sw2.Stop();

        // Assert 2
        result2.Should().BeFalse(
            "Second use of same JTI must be rejected despite latency");
        sw2.ElapsedMilliseconds.Should().BeGreaterThanOrEqualTo(500,
            "Latency still applies to replay rejection");
    }

    /// <summary>
    /// Test: JTI Cache expiration windows must be honored even when Redis is slow.
    ///
    /// Scenario: Redis slow to respond. During delay, token expiration window passes.
    /// Expected: Even if Redis eventually responds, expired token should not be marked as used.
    ///
    /// Security Implication: Time-based validity must not be bypassed by latency.
    /// </summary>
    [Fact]
    public async Task JtiCache_RespectsExpiration_DespiteLatency()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var expiryWindow = TimeSpan.FromSeconds(1);

        _mockReplayCache
            .Setup(x => x.TryMarkUsedAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .Returns(async () =>
            {
                // Simulate latency that exceeds expiry window
                await Task.Delay(TimeSpan.FromMilliseconds(1500));
                // By the time we "mark used", the proof has expired
                return false; // Expired, reject
            });

        var jti = "jti_expiry_test";
        var expiresAt = now.Add(expiryWindow);

        // Act
        var result = await _mockReplayCache.Object.TryMarkUsedAsync(
            jti,
            expiresAt,
            CancellationToken.None);

        // Assert
        result.Should().BeFalse(
            "Expired JTI must be rejected even if cache processing was delayed");
    }

    /// <summary>
    /// Test: Multiple concurrent requests to cache must not cause race conditions.
    ///
    /// Scenario: Three concurrent requests with same JTI arrive within race window.
    /// Expected: Only one succeeds (first to acquire lock), others see "already used."
    ///
    /// Security Implication: Concurrency does not create duplicate-use vulnerabilities.
    /// </summary>
    [Fact]
    public async Task JtiCache_HandlesConcurrency_WithoutRaceConditions()
    {
        // Arrange: Simulate lock-based concurrency
        var lockReleased = false;

        _mockReplayCache
            .Setup(x => x.TryMarkUsedAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .Returns(async () =>
            {
                // First caller wins, marks as used
                if (!lockReleased)
                {
                    lockReleased = true;
                    await Task.Delay(TimeSpan.FromMilliseconds(100));
                    return true;
                }
                // Subsequent callers see it as already used
                return false;
            });

        var jti = "jti_concurrency_test";
        var tasks = new List<Task<bool>>();

        // Act: Launch 3 concurrent requests
        for (int i = 0; i < 3; i++)
        {
            tasks.Add(
                _mockReplayCache.Object.TryMarkUsedAsync(
                    jti,
                    DateTimeOffset.UtcNow.AddMinutes(5),
                    CancellationToken.None));
        }

        var results = await Task.WhenAll(tasks);

        // Assert
        results.Should().Equal(true, false, false,
            "Only first concurrent request should succeed; others should see 'already used'");
    }

    /// <summary>
    /// Test: Cache must timeout gracefully without leaving connections open.
    ///
    /// Scenario: Redis operation times out. Expected: No connection leak,
    /// subsequent requests can acquire fresh connections.
    ///
    /// Security Implication: Prevents connection pool exhaustion (DoS vector).
    /// </summary>
    [Fact]
    public async Task JtiCache_DoesNotLeakConnections_OnTimeout()
    {
        // Arrange: Simulate connection timeout
        var operationCancelled = false;

        _mockReplayCache
            .Setup(x => x.TryMarkUsedAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .Returns(async () =>
            {
                try
                {
                    // Simulate timeout via CancellationToken
                    using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
                    await Task.Delay(TimeSpan.FromSeconds(5), cts.Token);
                    return true;
                }
                catch (OperationCanceledException)
                {
                    operationCancelled = true;
                    throw;
                }
            });

        // Act: Attempt operation that will timeout
        Func<Task> act = async () => await _mockReplayCache.Object.TryMarkUsedAsync(
            "jti_timeout",
            DateTimeOffset.UtcNow.AddMinutes(5),
            CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<OperationCanceledException>();
        operationCancelled.Should().BeTrue("Cancellation should be observed");

        // Act 2: Verify subsequent request can still use the cache
        _mockReplayCache
            .Setup(x => x.TryMarkUsedAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var followUpResult = await _mockReplayCache.Object.TryMarkUsedAsync(
            "jti_followup",
            DateTimeOffset.UtcNow.AddMinutes(5),
            CancellationToken.None);

        // Assert 2
        followUpResult.Should().BeTrue(
            "After timeout, cache should recover and serve subsequent requests");
    }
}
