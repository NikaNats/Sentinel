using Sentinel.Contracts.Shared;

namespace Sentinel.Contracts.Redis;

/// <summary>
///     CONTRACT: JTI replay-cache SET NX semantics.
///
///     Pins the "Set if Not eXists" behavior of RedisJtiReplayCache.TTryMarkUsedAsync —
///     the only correct primitive for replay protection. Key names, TTL clamps
///     and pseudo-state must never drift.
/// </summary>
[Collection(RedisContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "Redis 7.4 (StackExchange.Redis)")]
public sealed class JtiSetNxContractTests(RedisContractFixture fixture)
{
    private readonly RedisContractFixture _fixture = fixture;

    [Fact(DisplayName = "CONTRACT: first mark succeeds, duplicate mark fails (SET NX)")]
    public async Task Jti_TryMarkUsed_FailsOnReplay()
    {
        var cache = RedisContractFixture.JtiCache(_fixture.ProviderA);
        var jti = $"jti-{Guid.NewGuid():N}";

        var first = await cache.TryMarkUsedAsync(jti, DateTimeOffset.UtcNow.AddMinutes(5), cancellationToken: TestContext.Current.CancellationToken);
        first.Should().BeTrue("fresh jti MUST mark as used");

        var second = await cache.TryMarkUsedAsync(jti, DateTimeOffset.UtcNow.AddMinutes(5), cancellationToken: TestContext.Current.CancellationToken);
        second.Should().BeFalse("replayed jti MUST be rejected (SET NX semantics)");
    }

    [Fact(DisplayName = "CONTRACT: expired jti entry is no longer blocking (TTL release)")]
    public async Task Jti_ExpiredEntry_AllowsReuse()
    {
        var cache = RedisContractFixture.JtiCache(_fixture.ProviderA);
        var jti = $"jti-expired-{Guid.NewGuid():N}";

        // Store expiresAt in the past: store clamps to a 1s TTL (safe window).
        await cache.TryMarkUsedAsync(jti, DateTimeOffset.UtcNow.AddSeconds(-30), cancellationToken: TestContext.Current.CancellationToken);

        await Task.Delay(2500, TestContext.Current.CancellationToken);

        var reused = await cache.TryMarkUsedAsync(jti, DateTimeOffset.UtcNow.AddMinutes(5), cancellationToken: TestContext.Current.CancellationToken);
        reused.Should().BeTrue("expired replay window MUST allow a fresh token");
    }

    [Fact(DisplayName = "CONTRACT: raw SET NX is atomic — 20 concurrent calls, exactly one success")]
    public async Task Jti_RawSetNx_Concurrent_ExactlyOneWins()
    {
        var jti = $"raw-setnx-{Guid.NewGuid():N}";
        var key = new StackExchange.Redis.RedisKey($"jti:{jti}");

        var tasks = Enumerable.Range(0, 20).Select(_ =>
            _fixture.RawDatabase.StringSetAsync(key, "1", TimeSpan.FromMinutes(5),
                StackExchange.Redis.When.NotExists));

        var results = await Task.WhenAll(tasks);

        results.Count(winner => winner).Should().Be(1,
            "SET NX atomicity guarantees exactly one concurrent winner");
    }

    [Fact(DisplayName = "CONTRACT: distinct jti values do not collide")]
    public async Task Jti_DistinctValues_AreIndependent()
    {
        var cache = RedisContractFixture.JtiCache(_fixture.ProviderA);

        var first = await cache.TryMarkUsedAsync("jti-one", DateTimeOffset.UtcNow.AddMinutes(5), cancellationToken: TestContext.Current.CancellationToken);
        var second = await cache.TryMarkUsedAsync("jti-two", DateTimeOffset.UtcNow.AddMinutes(5), cancellationToken: TestContext.Current.CancellationToken);

        first.Should().BeTrue();
        second.Should().BeTrue("different jti MUST be independently markable");
    }
}