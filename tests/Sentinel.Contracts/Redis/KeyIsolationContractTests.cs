using Microsoft.Extensions.DependencyInjection;
using Sentinel.Contracts.Shared;
using Sentinel.Security.Abstractions.Session;

namespace Sentinel.Contracts.Redis;

/// <summary>
///     CONTRACT: Redis key-prefix isolation.
///
///     Sentinel deployments are multi-tenant: every cache entry MUST be namespaced
///     by the configured KeyPrefix, so data of one tenant is never readable or
///     consumable by another, even when sharing a Redis server.
/// </summary>
[Collection(RedisContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "Redis 7.4 (StackExchange.Redis)")]
public sealed class KeyIsolationContractTests(RedisContractFixture fixture)
{
    private readonly RedisContractFixture _fixture = fixture;

    [Fact(DisplayName = "CONTRACT: DPoP nonces never leak across key prefixes")]
    public async Task Nonce_IsIsolatedPerPrefix()
    {
        var storeA = RedisContractFixture.NonceStore(_fixture.ProviderA);
        var storeB = RedisContractFixture.NonceStore(_fixture.ProviderB);
        const string thumbprint = "cross-tenant-thumbprint";

        await storeA.SetNonceAsync(thumbprint, "tenant-a-secret", DateTimeOffset.UtcNow.AddMinutes(1), cancellationToken: TestContext.Current.CancellationToken);

        var fromA = await storeA.GetNonceAsync(thumbprint, TestContext.Current.CancellationToken);
        var fromB = await storeB.GetNonceAsync(thumbprint, TestContext.Current.CancellationToken);

        fromA.Should().Be("tenant-a-secret");
        fromB.Should().BeNull("tenant B MUST NOT see tenant A's nonce");

        var consumed = await storeB.ConsumeNonceIfMatchesAsync(thumbprint, "tenant-a-secret", cancellationToken: TestContext.Current.CancellationToken);
        consumed.Should().BeFalse("tenant B MUST NOT be able to consume tenant A's nonce");
    }

    [Fact(DisplayName = "CONTRACT: replay cache is isolated per prefix")]
    public async Task Jti_IsIsolatedPerPrefix()
    {
        var cacheA = RedisContractFixture.JtiCache(_fixture.ProviderA);
        var cacheB = RedisContractFixture.JtiCache(_fixture.ProviderB);
        const string jti = "cross-tenant-jti";

        await cacheA.TryMarkUsedAsync(jti, DateTimeOffset.UtcNow.AddMinutes(5), cancellationToken: TestContext.Current.CancellationToken);

        var inA = await cacheA.TryMarkUsedAsync(jti, DateTimeOffset.UtcNow.AddMinutes(5), cancellationToken: TestContext.Current.CancellationToken);
        var inB = await cacheB.TryMarkUsedAsync(jti, DateTimeOffset.UtcNow.AddMinutes(5), cancellationToken: TestContext.Current.CancellationToken);

        inA.Should().BeFalse("replay within tenant A must be blocked");
        inB.Should().BeTrue("tenant B's replay cache is a separate key space");
    }

    [Fact(DisplayName = "CONTRACT: session blacklist is isolated per prefix")]
    public async Task SessionBlacklist_IsIsolatedPerPrefix()
    {
        var blacklistA = _fixture.ProviderA.GetRequiredService<ISessionBlacklistCache>();
        var blacklistB = _fixture.ProviderB.GetRequiredService<ISessionBlacklistCache>();
        const string sessionId = "cross-tenant-session";

        await blacklistA.BlacklistSessionAsync(sessionId, DateTimeOffset.UtcNow.AddMinutes(30), cancellationToken: TestContext.Current.CancellationToken);

        (await blacklistA.IsBlacklistedAsync(sessionId, TestContext.Current.CancellationToken)).Should().BeTrue();
        (await blacklistB.IsBlacklistedAsync(sessionId, TestContext.Current.CancellationToken)).Should().BeFalse(
            "tenant B's sessions MUST NOT be revoked by tenant A's logout");
    }
}