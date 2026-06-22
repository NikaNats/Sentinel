using System.Collections.Concurrent;
using System.Reflection;
using FluentAssertions;
using Microsoft.Extensions.Time.Testing;
using Sentinel.AspNetCore.Stores;

namespace Sentinel.Tests.Unit.Unit;

public sealed class L1AntiFloodCacheTests
{
    private readonly L1AntiFloodCache _sut;
    private readonly FakeTimeProvider _timeProvider;
    private readonly TimeSpan _ttl;

    public L1AntiFloodCacheTests()
    {
        _timeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow);
        _ttl = TimeSpan.FromSeconds(3);
        _sut = new L1AntiFloodCache(_timeProvider, _ttl);
    }

    [Fact(DisplayName = "✅ RecordFailedAttempt blocks within TTL and expires exactly after")]
    public void RecordFailedAttempt_EnforcesTtlAndExpiresCorrectly()
    {
        const string targetId = "client-thumbprint-1";

        _sut.IsTemporarilyBlacklisted(targetId).Should().BeFalse();

        _sut.RecordFailedAttempt(targetId);

        _sut.IsTemporarilyBlacklisted(targetId).Should().BeTrue();

        _timeProvider.Advance(_ttl.Subtract(TimeSpan.FromMilliseconds(10)));
        _sut.IsTemporarilyBlacklisted(targetId).Should().BeTrue();

        _timeProvider.Advance(TimeSpan.FromMilliseconds(10));
        _sut.IsTemporarilyBlacklisted(targetId).Should().BeFalse();
    }

    [Fact(DisplayName = "🛡️ DoS Protection: Flood exceeds capacity but NEVER triggers complete wipeout")]
    public void RecordFailedAttempt_WhenFlooded_BoundsMemoryAndPreservesActiveKeys()
    {
        for (var i = 0; i < 50000; i++)
        {
            _sut.RecordFailedAttempt($"key-{i}");
        }

        const string criticalKey = "critical-active-key";
        _sut.RecordFailedAttempt(criticalKey);
        _sut.IsTemporarilyBlacklisted(criticalKey).Should().BeTrue();

        for (var i = 50000; i < 60000; i++)
        {
            _sut.RecordFailedAttempt($"spam-key-{i}");
        }

        _sut.IsTemporarilyBlacklisted(criticalKey).Should().BeTrue("Flood must NEVER wipe active blacklist entries.");

        var countProperty = typeof(L1AntiFloodCache)
            .GetField("_shortTermBlacklist", BindingFlags.NonPublic | BindingFlags.Instance);
        var blacklist = (ConcurrentDictionary<string, long>)countProperty!.GetValue(_sut)!;

        blacklist.Count.Should().BeLessThanOrEqualTo(50000, "Cache memory footprint must be strictly bounded.");
    }

    [Fact(DisplayName = "🌪️ Concurrency: Multiple threads writing and reading concurrently does not corrupt state")]
    public async Task MultiThreaded_HighContention_MaintainsInvariants()
    {
        const int threadCount = 10;
        const int itemsPerThread = 5000;
        var tasks = new Task[threadCount];

        for (var i = 0; i < threadCount; i++)
        {
            var threadId = i;
            tasks[i] = Task.Run(() =>
            {
                for (var j = 0; j < itemsPerThread; j++)
                {
                    _sut.RecordFailedAttempt($"thread-{threadId}-item-{j}");
                }
            });
        }

        await Task.WhenAll(tasks);

        _sut.IsTemporarilyBlacklisted("thread-0-item-0").Should().BeTrue();
    }

    [Fact(DisplayName = "🎯 Chronological Pruning: Expired items are pruned while active items are strictly preserved")]
    public void Pruning_OnlyEvictsExpiredItems()
    {
        _sut.RecordFailedAttempt("old-key-1");
        _sut.RecordFailedAttempt("old-key-2");

        _timeProvider.Advance(TimeSpan.FromSeconds(2));

        _sut.RecordFailedAttempt("new-key-1");

        _timeProvider.Advance(TimeSpan.FromSeconds(1.5));

        for (int i = 0; i < 49998; i++)
        {
            _sut.RecordFailedAttempt($"fill-key-{i}");
        }

        _sut.IsTemporarilyBlacklisted("old-key-1").Should().BeFalse("Expired items must be pruned.");
        _sut.IsTemporarilyBlacklisted("old-key-2").Should().BeFalse("Expired items must be pruned.");

        _sut.IsTemporarilyBlacklisted("new-key-1").Should().BeTrue("Active items must survive pruning.");
    }
}
