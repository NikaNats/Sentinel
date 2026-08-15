using System.Diagnostics.Metrics;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Redis;
using Sentinel.Redis.Stores;
using Sentinel.Security.Abstractions.Idempotency;
using Sentinel.Security.Diagnostics;
using StackExchange.Redis;

namespace Sentinel.Tests.Unit.Unit;

/// <summary>
///     Telemetry tests observe static OpenTelemetry instruments shared with other test
///     collections, so this collection must never run in parallel with them -
///     otherwise concurrent increments (e.g. RedisIdempotencyStoreTests) contaminate
///     the recorded measurements.
/// </summary>
[CollectionDefinition("TelemetryIsolation", DisableParallelization = true)]
public sealed class TelemetryIsolationCollection
{
}

/// <summary>
///     High-Assurance Telemetry Tests (SEC-ARCH-002, Section 6).
///
///     MISSION: prove the distributed-concurrency counters increment exactly once
///     per contention / nonce-mismatch event, so SRE alerting thresholds
///     (auth.dpop.nonce_mismatch_total, auth.idempotency.lock_contention_total)
///     reflect real security events without drift.
/// </summary>
[Collection("TelemetryIsolation")]
public sealed class DistributedTelemetryTests
{
    [Fact(DisplayName = "Telemetry: failed nonce consumption increments auth.dpop.nonce_mismatch_total")]
    public async Task ConsumeNonceIfMatchesAsync_WhenMismatch_IncrementsTelemetryCounter()
    {
        var providerMock = new Mock<IRedisConnectionProvider>();
        var muxMock = new Mock<IConnectionMultiplexer>();
        var dbMock = new Mock<IDatabase>();

        providerMock.Setup(p => p.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<IConnectionMultiplexer>(muxMock.Object));
        muxMock.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>()))
            .Returns(dbMock.Object);

        // Lua compare-and-delete returns 0 (mismatch / already consumed / stale).
        dbMock.Setup(d => d.ScriptEvaluateAsync(
                It.IsAny<string>(),
                It.IsAny<RedisKey[]>(),
                It.IsAny<RedisValue[]>()))
            .ReturnsAsync(RedisResult.Create((long)0));

        var sut = new RedisDpopNonceStore(
            providerMock.Object,
            new RedisOptions { KeyPrefix = "test:" },
            NullLogger<RedisDpopNonceStore>.Instance);

        using var probe = ListenToCounter(AuthTelemetry.DpopNonceMismatches);

        var result = await sut.ConsumeNonceIfMatchesAsync("thumbprint-1", "stale-nonce");

        result.Should().BeFalse();
        probe.Measurements.Sum().Should().Be(1, "exactly one mismatch event must be recorded");
    }

    [Fact(DisplayName = "Telemetry: successful nonce consumption does NOT increment mismatch counter")]
    public async Task ConsumeNonceIfMatchesAsync_WhenConsumed_DoesNotIncrementCounter()
    {
        var providerMock = new Mock<IRedisConnectionProvider>();
        var muxMock = new Mock<IConnectionMultiplexer>();
        var dbMock = new Mock<IDatabase>();

        providerMock.Setup(p => p.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<IConnectionMultiplexer>(muxMock.Object));
        muxMock.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>()))
            .Returns(dbMock.Object);

        dbMock.Setup(d => d.ScriptEvaluateAsync(
                It.IsAny<string>(),
                It.IsAny<RedisKey[]>(),
                It.IsAny<RedisValue[]>()))
            .ReturnsAsync(RedisResult.Create((long)1));

        var sut = new RedisDpopNonceStore(
            providerMock.Object,
            new RedisOptions { KeyPrefix = "test:" },
            NullLogger<RedisDpopNonceStore>.Instance);

        using var probe = ListenToCounter(AuthTelemetry.DpopNonceMismatches);

        var result = await sut.ConsumeNonceIfMatchesAsync("thumbprint-1", "current-nonce");

        result.Should().BeTrue();
        probe.Measurements.Should().BeEmpty("successful consumption must not count as a mismatch");
    }

    [Fact(DisplayName = "Telemetry: idempotency lock contention increments auth.idempotency.lock_contention_total")]
    public async Task TryAcquireAsync_WhenLockHeld_IncrementsContentionCounter()
    {
        var providerMock = new Mock<IRedisConnectionProvider>();
        var muxMock = new Mock<IConnectionMultiplexer>();
        var dbMock = new Mock<IDatabase>();

        providerMock.Setup(p => p.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<IConnectionMultiplexer>(muxMock.Object));
        muxMock.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>()))
            .Returns(dbMock.Object);

        // SET NX fails (another pod holds the lock), and the lock is still IN_PROGRESS.
        dbMock.Setup(d => d.StringSetAsync(
                It.IsAny<RedisKey>(),
                It.IsAny<RedisValue>(),
                It.IsAny<TimeSpan>(),
                It.IsAny<When>(),
                It.IsAny<CommandFlags>()))
            .ReturnsAsync(false);
        dbMock.Setup(d => d.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync((RedisValue)"IN_PROGRESS");

        var sut = new RedisIdempotencyStore(
            providerMock.Object,
            NullLogger<RedisIdempotencyStore>.Instance);

        using var probe = ListenToCounter(AuthTelemetry.IdempotencyLockContentions);

        var (state, _) = await sut.TryAcquireAsync("key-1", TimeSpan.FromSeconds(5));

        state.Should().Be(IdempotencyAcquireResult.InProgress);
        probe.Measurements.Sum().Should().Be(1, "exactly one contention event must be recorded");
    }

    [Fact(DisplayName = "Telemetry: uncontended idempotency acquisition does NOT increment contention counter")]
    public async Task TryAcquireAsync_WhenLockFree_DoesNotIncrementContentionCounter()
    {
        var providerMock = new Mock<IRedisConnectionProvider>();
        var muxMock = new Mock<IConnectionMultiplexer>();
        var dbMock = new Mock<IDatabase>();

        providerMock.Setup(p => p.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<IConnectionMultiplexer>(muxMock.Object));
        muxMock.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>()))
            .Returns(dbMock.Object);

        dbMock.Setup(d => d.StringSetAsync(
                It.IsAny<RedisKey>(),
                It.IsAny<RedisValue>(),
                It.IsAny<TimeSpan>(),
                It.IsAny<When>(),
                It.IsAny<CommandFlags>()))
            .ReturnsAsync(true);

        var sut = new RedisIdempotencyStore(
            providerMock.Object,
            NullLogger<RedisIdempotencyStore>.Instance);

        using var probe = ListenToCounter(AuthTelemetry.IdempotencyLockContentions);

        var (state, _) = await sut.TryAcquireAsync("key-1", TimeSpan.FromSeconds(5));

        state.Should().Be(IdempotencyAcquireResult.Acquired);
        probe.Measurements.Should().BeEmpty("uncontended acquisition must not count as contention");
    }

    /// <summary>
    ///     Subscribes to a specific counter instrument and collects every measurement
    ///     recorded while the listener is active (the listener MUST be started before
    ///     the act under test - counters do not expose cumulative values).
    /// </summary>
    private static TelemetryProbe ListenToCounter(Instrument instrument)
    {
        var probe = new TelemetryProbe();
        probe.Listener.InstrumentPublished = (i, l) =>
        {
            if (ReferenceEquals(i, instrument))
            {
                l.EnableMeasurementEvents(i);
            }
        };
        probe.Listener.SetMeasurementEventCallback<long>((i, measurement, _, _) =>
        {
            if (ReferenceEquals(i, instrument))
            {
                probe.Measurements.Add(measurement);
            }
        });
        probe.Listener.EnableMeasurementEvents(instrument);
        probe.Listener.Start();
        return probe;
    }

    private sealed class TelemetryProbe : IDisposable
    {
        public List<long> Measurements { get; } = new();

        public MeterListener Listener { get; } = new();

        public void Dispose() => Listener.Dispose();
    }
}
