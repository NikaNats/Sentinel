using Microsoft.EntityFrameworkCore;
using Sentinel.Contracts.Shared;
using Sentinel.EntityFrameworkCore.Models;

namespace Sentinel.Contracts.Postgres;

/// <summary>
///     CONTRACT: unique-constraint behavior at the database level.
///
///     Jti / thumbprint / sessionId are keyed on UNIQUE columns — the database
///     itself must reject duplicates regardless of application logic. This pins
///     that the REAL PostgreSQL DDL enforces identity.
/// </summary>
[Collection(PostgreSqlContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "PostgreSQL 17 (Npgsql + EF Core)")]
public sealed class UniqueConstraintContractTests(PostgreSqlContractFixture fixture)
{
    private readonly PostgreSqlContractFixture _fixture = fixture;

    [Fact(DisplayName = "CONTRACT: duplicate jti row is rejected by the database")]
    public async Task Jti_DuplicateKey_ThrowsOnSave()
    {
        const string jti = "unique-jti";
        
        // 1. Insert the first record and dispose the context
        await using (var context1 = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString))
        {
            context1.JtiReplayCache.Add(new JtiReplayCacheEntry { Jti = jti, ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60) });
            await context1.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        // 2. Use a FRESH context to bypass the in-memory Change Tracker
        await using (var context2 = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString))
        {
            context2.JtiReplayCache.Add(new JtiReplayCacheEntry { Jti = jti, ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60) });
            
            var act = async () => await context2.SaveChangesAsync(cancellationToken: TestContext.Current.CancellationToken);
            await act.Should().ThrowAsync<DbUpdateException>("the PK/unique constraint MUST reject the duplicate");
        }
    }

    [Fact(DisplayName = "CONTRACT: duplicate nonce thumbprint is rejected by the database")]
    public async Task Nonce_DuplicateThumbprint_Throws()
    {
        var thumbprint = $"unique-tp-{Guid.NewGuid():N}";
        
        // 1. Insert the first record and dispose the context
        await using (var context1 = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString))
        {
            context1.DpopNonceStore.Add(new DpopNonceEntry { Thumbprint = thumbprint, Nonce = "n1", ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60) });
            await context1.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        // 2. Use a FRESH context to bypass the in-memory Change Tracker
        await using (var context2 = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString))
        {
            context2.DpopNonceStore.Add(new DpopNonceEntry { Thumbprint = thumbprint, Nonce = "n2", ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60) });
            
            var act = async () => await context2.SaveChangesAsync(cancellationToken: TestContext.Current.CancellationToken);
            await act.Should().ThrowAsync<DbUpdateException>();
        }
    }

    [Fact(DisplayName = "CONTRACT: duplicate session id is rejected by the database")]
    public async Task Session_DuplicateId_ThrowsOnSave()
    {
        var sessionId = $"unique-session-{Guid.NewGuid():N}";
        
        // 1. Insert the first record and dispose the context
        await using (var context1 = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString))
        {
            context1.SessionBlacklist.Add(new SessionBlacklistEntry { SessionId = sessionId, ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60) });
            await context1.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        // 2. Use a FRESH context to bypass the in-memory Change Tracker
        await using (var context2 = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString))
        {
            context2.SessionBlacklist.Add(new SessionBlacklistEntry { SessionId = sessionId, ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60) });
            
            var act = async () => await context2.SaveChangesAsync(cancellationToken: TestContext.Current.CancellationToken);
            await act.Should().ThrowAsync<DbUpdateException>();
        }
    }

    [Fact(DisplayName = "CONTRACT: single row survives a unique-violation attempt")]
    public async Task Duplicate_Insert_LeavesSingleRow()
    {
        const string jti = "unique-survivor";
        
        // 1. Insert the first record and dispose the context
        await using (var context1 = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString))
        {
            context1.JtiReplayCache.Add(new JtiReplayCacheEntry { Jti = jti, ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60) });
            await context1.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        // 2. Use a FRESH context for the duplicate attempt
        await using (var context2 = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString))
        {
            context2.JtiReplayCache.Add(new JtiReplayCacheEntry { Jti = jti, ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-60) });
            try
            {
                await context2.SaveChangesAsync(cancellationToken: TestContext.Current.CancellationToken);
            }
            catch (DbUpdateException)
            {
                // expected
            }
        }

        // 3. Verify with a THIRD fresh context
        await using (var context3 = PostgreSqlContractFixture.CreateContext(_fixture.ConnectionString))
        {
            var count = await context3.JtiReplayCache.CountAsync(e => e.Jti == jti, TestContext.Current.CancellationToken);
            count.Should().Be(1, "a rejected duplicate MUST NOT leave a second row behind");
        }
    }
}