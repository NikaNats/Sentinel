using Microsoft.Extensions.DependencyInjection;
using Sentinel.Contracts.Shared;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;

namespace Sentinel.Contracts.Postgres;

/// <summary>
///     CONTRACT: race-safe semantics under real concurrent load.
///
///     Pins the two atomic primitives of the sql stores under parallel callers:
///     the UNIQUE-constraint INSERT for replay marking and the single
///     DELETE-statement nonce consumption. Exactly one caller may win each race.
/// </summary>
[Collection(PostgreSqlContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "PostgreSQL 17 (Npgsql + EF Core)")]
public sealed class ConcurrencySemanticsContractTests(PostgreSqlContractFixture fixture)
{
    private readonly PostgreSqlContractFixture _fixture = fixture;

    [Fact(DisplayName = "CONTRACT: exactly one concurrent jti mark wins the race")]
    public async Task Jti_ConcurrentMarking_HasExactlyOneWinner()
    {
        using var provider = PostgreSqlContractFixture.BuildProvider(_fixture.ConnectionString);
        var jti = $"race-jti-{Guid.NewGuid():N}";

        var results = await Task.WhenAll(
            Mark(provider, jti),
            Mark(provider, jti));

        results.Count(winner => winner).Should().Be(1,
            "exactly one concurrent replay mark MUST win (unique constraint)");
    }

    [Fact(DisplayName = "CONTRACT: exactly one concurrent nonce consume succeeds")]
    public async Task Nonce_ConcurrentConsume_HasExactlyOneWinner()
    {
        using var provider = PostgreSqlContractFixture.BuildProvider(_fixture.ConnectionString);
        var thumbprint = $"race-tp-{Guid.NewGuid():N}";

        await ConsumeAsync(provider, thumbprint, "race-nonce", setupOnly: true);

        var results = await Task.WhenAll(
            ConsumeAsync(provider, thumbprint, "race-nonce"),
            ConsumeAsync(provider, thumbprint, "race-nonce"));

        results.Count(winner => winner).Should().Be(1,
            "exactly one concurrent consume MUST win (single-statement delete)");
    }

    private static async Task<bool> Mark(ServiceProvider provider, string jti)
    {
        using var scope = provider.CreateScope();
        var cache = scope.ServiceProvider.GetRequiredService<IJtiReplayCache>();
        return await cache.TryMarkUsedAsync(jti, DateTimeOffset.UtcNow.AddMinutes(5));
    }

    private static async Task<bool> ConsumeAsync(
        ServiceProvider provider,
        string thumbprint,
        string nonce,
        bool setupOnly = false)
    {
        using var scope = provider.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IDpopNonceStore>();

        if (setupOnly)
        {
            await store.SetNonceAsync(thumbprint, nonce, DateTimeOffset.UtcNow.AddMinutes(5));
            return false;
        }

        return await store.ConsumeNonceIfMatchesAsync(thumbprint, nonce);
    }
}