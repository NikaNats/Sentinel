using Microsoft.Extensions.DependencyInjection;
using Sentinel.Contracts.Shared;
using Sentinel.Security.Abstractions.Session;
using StackExchange.Redis;

namespace Sentinel.Contracts.Redis;

/// <summary>
///     CONTRACT: TTL precision &amp; key layout on real Redis.
///
///     Pins:
///     * nonce   keys = {prefix}nonce:{thumbprint}, TTL ≈ configured expiry,
///     * jti     keys = {prefix}jti:{jti},
///     * session keys = {prefix}session:{sessionId},
///     and physical expiry within the pin window (+/‑1s Redis precision).
/// </summary>
[Collection(RedisContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "Redis 7.4 (StackExchange.Redis)")]
public sealed class TtlPrecisionContractTests(RedisContractFixture fixture)
{
    private const string Prefix = "ttl-prefix:";

    private readonly RedisContractFixture _fixture = fixture;

    [Fact(DisplayName = "CONTRACT: nonce lives at {prefix}nonce:{{thumbprint}} with TTL ≈ expiry")]
    public async Task Nonce_KeyLayout_AndTtlPrecision()
    {
        await using var provider = _fixture.Build(Prefix);
        var store = RedisContractFixture.NonceStore(provider);
        const string thumbprint = "ttl-nonce";

        await store.SetNonceAsync(thumbprint, "ttl-value", DateTimeOffset.UtcNow.AddSeconds(10), cancellationToken: TestContext.Current.CancellationToken);

        var value = await _fixture.RawDatabase.StringGetAsync(new RedisKey($"{Prefix}nonce:{thumbprint}"));
        value.ToString().Should().Be("ttl-value", "nonce must live under the pinned key");

        var ttl = await _fixture.RawDatabase.KeyTimeToLiveAsync(new RedisKey($"{Prefix}nonce:{thumbprint}"));
        ttl.Should().NotBeNull("nonce MUST expire");
        ttl!.Value.TotalSeconds.Should().BeInRange(8, 12, "TTL must track the configured expiry (±2s)");
    }

    [Fact(DisplayName = "CONTRACT: raw TTL accuracy is within Redis' 1-second precision")]
    public async Task Raw_TtlPrecision_WithinOneSecond()
    {
        var key = new RedisKey($"contract:ttl-raw:{Guid.NewGuid():N}");
        var requested = TimeSpan.FromSeconds(300);

        await _fixture.RawDatabase.StringSetAsync(key, "v", requested);

        var actual = await _fixture.RawDatabase.KeyTimeToLiveAsync(key);
        actual.Should().NotBeNull();
        var drift = Math.Abs((actual!.Value - requested).TotalSeconds);
        drift.Should().BeLessThanOrEqualTo(1,
            "Redis TTL must honor the requested expiry to ±1s precision");
    }

    [Fact(DisplayName = "CONTRACT: jti entries live at {prefix}jti:{{jti}} with expiry TTL")]
    public async Task Jti_StoreKey_AndExpiryTtl()
    {
        await using var provider = _fixture.Build(Prefix);
        var cache = RedisContractFixture.JtiCache(provider);
        var jti = $"jti-{Guid.NewGuid():N}";

        await cache.TryMarkUsedAsync(jti, DateTimeOffset.UtcNow.AddSeconds(30), cancellationToken: TestContext.Current.CancellationToken);

        var ttl = await _fixture.RawDatabase.KeyTimeToLiveAsync(new RedisKey($"{Prefix}jti:{jti}"));
        ttl.Should().NotBeNull("replay-cache entries MUST expire");
        ttl!.Value.TotalSeconds.Should().BeLessThanOrEqualTo(30);
    }

    [Fact(DisplayName = "CONTRACT: expired blacklisted sessions physically disappear")]
    public async Task Session_StoreExpiredEntry_IsGone()
    {
        await using var provider = _fixture.Build(Prefix);
        var blacklist = provider.GetRequiredService<ISessionBlacklistCache>();

        await blacklist.BlacklistSessionAsync("expired-session", DateTimeOffset.UtcNow.AddSeconds(2), cancellationToken: TestContext.Current.CancellationToken);
        await Task.Delay(3500, TestContext.Current.CancellationToken);

        var value = await _fixture.RawDatabase.StringGetAsync(new RedisKey($"{Prefix}session:expired-session"));
        value.IsNullOrEmpty.Should().BeTrue("expired session MUST be physically gone");
    }
}