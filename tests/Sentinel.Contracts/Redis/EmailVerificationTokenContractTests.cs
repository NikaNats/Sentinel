using Sentinel.Contracts.Shared;
using Sentinel.Redis.Stores;

namespace Sentinel.Contracts.Redis;

/// <summary>
///     CONTRACT: Email verification token store semantics.
///
///     Pins the single-use (SET NX + GETDEL) behavior of EmailVerificationTokenStore —
///     a verification token must bind to exactly one Keycloak user, be consumable
///     exactly once, and never survive its TTL window.
/// </summary>
[Collection(RedisContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "Redis 7.4 (StackExchange.Redis)")]
public sealed class EmailVerificationTokenContractTests(RedisContractFixture fixture)
{
    private readonly EmailVerificationTokenStore _store = new(fixture.RawMultiplexer);

    [Fact(DisplayName = "CONTRACT: fresh token stores; duplicate token is rejected (SET NX)")]
    public async Task Store_FreshTokenSucceeds_DuplicateRejected()
    {
        var token = $"evt-{Guid.NewGuid():N}";
        var ttl = TimeSpan.FromMinutes(10);

        var first = await _store.StoreAsync(token, "kc-user-1", ttl, TestContext.Current.CancellationToken);
        first.Should().BeTrue("a fresh verification token MUST be stored");

        var duplicate = await _store.StoreAsync(token, "kc-user-2", ttl, TestContext.Current.CancellationToken);
        duplicate.Should().BeFalse("re-storing the same token MUST NOT overwrite the original binding");
    }

    [Fact(DisplayName = "CONTRACT: consume returns the bound user exactly once (GETDEL single-use)")]
    public async Task Consume_ReturnsUserOnce_ThenTokenIsSpent()
    {
        var token = $"evt-{Guid.NewGuid():N}";
        await _store.StoreAsync(token, "kc-user-42", TimeSpan.FromMinutes(10), TestContext.Current.CancellationToken);

        var first = await _store.ConsumeAsync(token, TestContext.Current.CancellationToken);
        first.Should().Be("kc-user-42", "the first consumption MUST return the bound Keycloak user ID");

        var second = await _store.ConsumeAsync(token, TestContext.Current.CancellationToken);
        second.Should().BeNull("single-use semantics MUST delete the token after consumption");
    }

    [Fact(DisplayName = "CONTRACT: consuming an unknown token yields null (no false positives)")]
    public async Task Consume_UnknownToken_ReturnsNull()
    {
        var result = await _store.ConsumeAsync($"evt-unknown-{Guid.NewGuid():N}", TestContext.Current.CancellationToken);
        result.Should().BeNull();
    }
}
