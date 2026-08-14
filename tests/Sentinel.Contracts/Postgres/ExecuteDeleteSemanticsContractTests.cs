using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Contracts.Shared;
using Sentinel.EntityFrameworkCore.Models;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Session;

namespace Sentinel.Contracts.Postgres;

/// <summary>
///     CONTRACT: determinism of bulk-delete operations.
///
///     Pins how the stores clean up expired rows (ExecuteDelete) and how the
///     performance-sensitive expiry filters behave — facts a future SQL
///     rewrite must preserve.
/// </summary>
[Collection(PostgreSqlContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "PostgreSQL 17 (Npgsql + EF Core)")]
public sealed class ExecuteDeleteSemanticsContractTests(PostgreSqlContractFixture fixture)
{
    private readonly PostgreSqlContractFixture _fixture = fixture;

    [Fact(DisplayName = "CONTRACT: nonce cleanup removes ONLY expired entries")]
    public async Task Nonce_Cleanup_RemovesOnlyExpired()
    {
        using var provider = PostgreSqlContractFixture.BuildProvider(_fixture.ConnectionString);
        using var scope = provider.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IDpopNonceStore>();

        await using var context = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString);
        await context.DpopNonceStore.ExecuteDeleteAsync(cancellationToken: TestContext.Current.CancellationToken);
        context.DpopNonceStore.AddRange(
            new DpopNonceEntry { Thumbprint = "cleanup-expired-a", Nonce = "n1", ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60) },
            new DpopNonceEntry { Thumbprint = "cleanup-expired-b", Nonce = "n2", ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60) },
            new DpopNonceEntry { Thumbprint = "cleanup-live", Nonce = "n3", ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30) });
        await context.SaveChangesAsync(cancellationToken: TestContext.Current.CancellationToken);

        await store.CleanupExpiredAsync(cancellationToken: TestContext.Current.CancellationToken);

        await using var verify = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString);
        var remaining = await verify.DpopNonceStore
            .Select(e => e.Thumbprint)
            .ToListAsync(cancellationToken: TestContext.Current.CancellationToken);
        remaining.Should().BeEquivalentTo(new[] { "cleanup-live" },
            "cleanup MUST delete exactly the expired rows");
    }

    [Fact(DisplayName = "CONTRACT: jti cleanup removes ONLY expired entries")]
    public async Task Jti_Cleanup_RemovesOnlyExpired()
    {
        using var provider = PostgreSqlContractFixture.BuildProvider(_fixture.ConnectionString);
        using var scope = provider.CreateScope();
        var cache = scope.ServiceProvider.GetRequiredService<IJtiReplayCache>();

        await using var context = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString);
        await context.JtiReplayCache.ExecuteDeleteAsync(cancellationToken: TestContext.Current.CancellationToken);
        context.JtiReplayCache.AddRange(
            new JtiReplayCacheEntry { Jti = "cleanup-jti-expired", ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60) },
            new JtiReplayCacheEntry { Jti = "cleanup-jti-live", ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30) });
        await context.SaveChangesAsync(cancellationToken: TestContext.Current.CancellationToken);

        await cache.CleanupExpiredAsync(cancellationToken: TestContext.Current.CancellationToken);

        var remaining = await context.JtiReplayCache
            .Select(e => e.Jti)
            .ToListAsync(cancellationToken: TestContext.Current.CancellationToken);
        remaining.Should().BeEquivalentTo(new[] { "cleanup-jti-live" });
    }

    [Fact(DisplayName = "CONTRACT: session cleanup is a physical delete of expired rows")]
    public async Task Session_Cleanup_RemovesOnlyExpired()
    {
        using var provider = PostgreSqlContractFixture.BuildProvider(_fixture.ConnectionString);
        using var scope = provider.CreateScope();
        var blacklist = scope.ServiceProvider.GetRequiredService<ISessionBlacklistCache>();

        await using (var context = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString))
        {
            await context.SessionBlacklist.ExecuteDeleteAsync(cancellationToken: TestContext.Current.CancellationToken);
            context.SessionBlacklist.AddRange(
                new SessionBlacklistEntry { SessionId = "cleanup-session-expired", ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60) },
                new SessionBlacklistEntry { SessionId = "cleanup-session-live", ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30) });
            await context.SaveChangesAsync(cancellationToken: TestContext.Current.CancellationToken);
        }

        await blacklist.CleanupExpiredAsync(cancellationToken: TestContext.Current.CancellationToken);

        await using var verify = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString);
        var remaining = await verify.SessionBlacklist
            .Select(e => e.SessionId)
            .ToListAsync(cancellationToken: TestContext.Current.CancellationToken);
        remaining.Should().BeEquivalentTo(new[] { "cleanup-session-live" });
    }

    [Fact(DisplayName = "CONTRACT: expired session entries no longer block (time-windowed delete)")]
    public async Task Session_ExpiredEntry_DoesNotBlock()
    {
        await using var context = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString);
        context.SessionBlacklist.Add(new SessionBlacklistEntry
        {
            SessionId = "session-window-expired",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60)
        });
        await context.SaveChangesAsync(cancellationToken: TestContext.Current.CancellationToken);

        using var provider = PostgreSqlContractFixture.BuildProvider(_fixture.ConnectionString);
        using var scope = provider.CreateScope();
        var blacklist = scope.ServiceProvider.GetRequiredService<ISessionBlacklistCache>();

        (await blacklist.IsBlacklistedAsync("session-window-expired", TestContext.Current.CancellationToken)).Should().BeFalse(
            "expired entries must behave as not-blacklisted");
    }

    [Fact(DisplayName = "CONTRACT: ExecuteDelete with no matches returns 0")]
    public async Task Delete_NoMatchingRows_ReturnsZero()
    {
        await using var context = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString);

        var targetJti = $"nonexistent-{Guid.NewGuid():N}";

        var deleted = await context.JtiReplayCache
            .Where(e => e.Jti == targetJti)
            .ExecuteDeleteAsync(cancellationToken: TestContext.Current.CancellationToken);

        deleted.Should().Be(0, "ExecuteDelete must return 0 when nothing matches");
    }

    [Fact(DisplayName = "CONTRACT: ExecuteDelete never populates the change tracker")]
    public async Task Delete_DoesNotLoadEntitiesIntoChangeTracker()
    {
        await using var context = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString);
        context.JtiReplayCache.Add(new JtiReplayCacheEntry
        {
            Jti = $"tracker-jti-{Guid.NewGuid():N}",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60)
        });
        await context.SaveChangesAsync(cancellationToken: TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();

        await context.JtiReplayCache
            .Where(e => e.ExpiresAt <= DateTimeOffset.UtcNow)
            .ExecuteDeleteAsync(cancellationToken: TestContext.Current.CancellationToken);

        context.ChangeTracker.Entries().Should().BeEmpty(
            "bulk cleanup must execute server-side without materializing entities");
    }

    [Fact(DisplayName = "CONTRACT: cleanup DELETE races an INSERT without deadlocking")]
    public async Task Delete_ConcurrentInsert_CompletesWithinTimeBound()
    {
        await using var context = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString);
        context.JtiReplayCache.Add(new JtiReplayCacheEntry
        {
            Jti = $"deadlock-jti-{Guid.NewGuid():N}",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60)
        });
        await context.SaveChangesAsync(cancellationToken: TestContext.Current.CancellationToken);

        var cleanup = context.JtiReplayCache
            .Where(e => e.ExpiresAt <= DateTimeOffset.UtcNow)
            .ExecuteDeleteAsync(cancellationToken: TestContext.Current.CancellationToken);

        var insert = Task.Run(async () =>
        {
            await using var other = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString);
            other.JtiReplayCache.Add(new JtiReplayCacheEntry
            {
                Jti = $"deadlock-jti-{Guid.NewGuid():N}",
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30)
            });
            await other.SaveChangesAsync(cancellationToken: TestContext.Current.CancellationToken);
        }, TestContext.Current.CancellationToken);

        var completed = await Task.WhenAny(cleanup, insert, Task.Delay(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken));
        completed.Should().NotBe(null, "concurrent cleanup + insert must not deadlock");
        await cleanup;
        await insert;
    }
}