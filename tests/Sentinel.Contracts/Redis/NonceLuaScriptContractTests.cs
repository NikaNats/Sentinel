using Sentinel.Contracts.Shared;
using Sentinel.Security.Abstractions.Nonce;

namespace Sentinel.Contracts.Redis;

/// <summary>
///     CONTRACT: DPoP nonce Lua compare-and-delete semantics.
///
///     Pins the atomic semantics of the Lua script embedded in
///     RedisDpopNonceStore: consume-once, no-delete-on-mismatch, clear-by-empty.
/// </summary>
[Collection(RedisContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "Redis 7.4 (StackExchange.Redis)")]
public sealed class NonceLuaScriptContractTests(RedisContractFixture fixture)
{
    private readonly RedisContractFixture _fixture = fixture;

    [Fact(DisplayName = "CONTRACT: nonce round-trips through the store (SET + GET)")]
    public async Task Nonce_SetThenGet_ReturnsSameValue()
    {
        var store = RedisContractFixture.NonceStore(_fixture.ProviderA);
        const string thumbprint = "roundtrip-thumbprint";
        var nonce = $"nonce-{Guid.NewGuid():N}";

        await store.SetNonceAsync(thumbprint, nonce, DateTimeOffset.UtcNow.AddMinutes(1), cancellationToken: TestContext.Current.CancellationToken);

        var retrieved = await store.GetNonceAsync(thumbprint, TestContext.Current.CancellationToken);

        retrieved.Should().Be(nonce, "nonce must round-trip byte-identically");
    }

    [Fact(DisplayName = "CONTRACT: matching nonce is consumed exactly once (Lua atomic delete)")]
    public async Task Nonce_MatchingValue_ConsumesOnceAndDeletes()
    {
        var store = RedisContractFixture.NonceStore(_fixture.ProviderA);
        const string thumbprint = "consume-once-thumbprint";
        const string nonce = "consume-once-value";

        await store.SetNonceAsync(thumbprint, nonce, DateTimeOffset.UtcNow.AddMinutes(1), cancellationToken: TestContext.Current.CancellationToken);

        var first = await store.ConsumeNonceIfMatchesAsync(thumbprint, nonce, cancellationToken: TestContext.Current.CancellationToken);
        first.Should().BeTrue("matching nonce must be consumed");

        var after = await store.GetNonceAsync(thumbprint, TestContext.Current.CancellationToken);
        after.Should().BeNull("consumed nonce must be deleted from Redis");

        var second = await store.ConsumeNonceIfMatchesAsync(thumbprint, nonce, cancellationToken: TestContext.Current.CancellationToken);
        second.Should().BeFalse("re-consumption of a deleted nonce must fail");
    }

    [Fact(DisplayName = "CONTRACT: mismatched nonce is NOT deleted (Lua returns 0)")]
    public async Task Nonce_MismatchedValue_IsNotDeleted()
    {
        var store = RedisContractFixture.NonceStore(_fixture.ProviderA);
        const string thumbprint = "mismatch-thumbprint";

        await store.SetNonceAsync(thumbprint, "expected-value", DateTimeOffset.UtcNow.AddMinutes(1), cancellationToken: TestContext.Current.CancellationToken);

        var result = await store.ConsumeNonceIfMatchesAsync(thumbprint, "wrong-value", cancellationToken: TestContext.Current.CancellationToken);

        result.Should().BeFalse("mismatched nonce must not be consumed");

        var retained = await store.GetNonceAsync(thumbprint, TestContext.Current.CancellationToken);
        retained.Should().Be("expected-value", "mismatch MUST NOT delete the stored nonce");
    }

    [Fact(DisplayName = "CONTRACT: empty nonce clears the entry (middleware protocol)")]
    public async Task Nonce_EmptyValue_ClearsEntry()
    {
        var store = RedisContractFixture.NonceStore(_fixture.ProviderA);
        const string thumbprint = "clear-thumbprint";

        await store.SetNonceAsync(thumbprint, "to-be-cleared", DateTimeOffset.UtcNow.AddMinutes(1), cancellationToken: TestContext.Current.CancellationToken);
        await store.SetNonceAsync(thumbprint, string.Empty, DateTimeOffset.UtcNow.AddMinutes(1), cancellationToken: TestContext.Current.CancellationToken);

        var retrieved = await store.GetNonceAsync(thumbprint, TestContext.Current.CancellationToken);
        retrieved.Should().BeNull("empty nonce signals 'clear by empty' and must delete the entry");
    }

    [Fact(DisplayName = "CONTRACT: 10 parallel consumers — exactly one wins (Lua atomicity)")]
    public async Task Nonce_ConcurrentConsumptions_ExactlyOneWins()
    {
        var store = RedisContractFixture.NonceStore(_fixture.ProviderA);
        const string thumbprint = "concurrent-thumbprint";
        const string nonce = "concurrent-nonce";

        await store.SetNonceAsync(thumbprint, nonce, DateTimeOffset.UtcNow.AddMinutes(1), cancellationToken: TestContext.Current.CancellationToken);

        var tasks = Enumerable.Range(0, 10).Select(_ =>
            store.ConsumeNonceIfMatchesAsync(thumbprint, nonce, cancellationToken: TestContext.Current.CancellationToken));

        var results = await Task.WhenAll(tasks);

        results.Count(winner => winner).Should().Be(1,
            "the Lua compare-and-delete MUST yield exactly one winner (atomicity guarantee)");
    }

    [Fact(DisplayName = "CONTRACT: unknown thumbprint returns null (no nonce state)")]
    public async Task Nonce_UnknownThumbprint_ReturnsNull()
    {
        var store = RedisContractFixture.NonceStore(_fixture.ProviderA);

        var retrieved = await store.GetNonceAsync($"missing-{Guid.NewGuid():N}", TestContext.Current.CancellationToken);

        retrieved.Should().BeNull();
    }
}