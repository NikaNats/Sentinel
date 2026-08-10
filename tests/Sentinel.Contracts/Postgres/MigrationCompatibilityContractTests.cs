using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Contracts.Shared;
using Npgsql;

namespace Sentinel.Contracts.Postgres;

/// <summary>
///     CONTRACT: EF migrations &amp; DDL pinning.
///
///     The security-cache schema is created by compile-time migrations, not ad-hoc
///     SQL. This pins: clean-database migration succeeds, re-migration is
///     idempotent, and the exact tables/columns exist in the pinned schema.
/// </summary>
[Collection(PostgreSqlContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "PostgreSQL 17 (Npgsql + EF Core)")]
public sealed class MigrationCompatibilityContractTests(PostgreSqlContractFixture fixture)
{
    private readonly PostgreSqlContractFixture _fixture = fixture;

    [Fact(DisplayName = "CONTRACT: migrations apply cleanly to a fresh database and are idempotent")]
    public async Task Migrations_ApplyCleanly_AndAreIdempotent()
    {
        var database = $"sentinel_migration_check_{Guid.NewGuid():N}";
        var connectionString = await _fixture.CreateDatabaseAsync(database);

        await using (var context = PostgreSqlContractFixture.CreateContext(connectionString))
        {
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);

            var applied = await context.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken);
            applied.Should().NotBeEmpty("migration history must be persisted");
            applied.First().Should().Contain("InitialSecurityDb");
        }

        // Second migrate on the same database must be a no-op (idempotency contract).
        await using (var context = PostgreSqlContractFixture.CreateContext(connectionString))
        {
            var act = async () => await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
            await act.Should().NotThrowAsync("re-applying migrations must be idempotent");
        }
    }

    [Fact(DisplayName = "CONTRACT: all security-cache tables exist under the security_cache schema")]
    public async Task Schema_HasExpectedTables()
    {
        var connectionString = _fixture.ConnectionString;
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);

        var tables = new List<string>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'security_cache'
                ORDER BY table_name
                """;
            await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
            while (await reader.ReadAsync(TestContext.Current.CancellationToken))
            {
                tables.Add(reader.GetString(0));
            }
        }

        tables.Should().Contain(new[]
        {
            "jti_replay_cache",
            "dpop_nonce_store",
            "session_blacklist"
        });
    }

    [Fact(DisplayName = "CONTRACT: exact column set of each cache table")]
    public async Task Schema_HasExpectedColumns()
    {
        var connectionString = _fixture.ConnectionString;
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);

        var expected = new Dictionary<string, string[]>
        {
            ["jti_replay_cache"] = ["id", "expires_at", "created_at"],
            ["dpop_nonce_store"] = ["id", "nonce", "expires_at", "created_at"],
            ["session_blacklist"] = ["id", "expires_at", "created_at"]
        };

        foreach (var (table, columns) in expected)
        {
            var actual = new List<string>();
            await using (var command = connection.CreateCommand())
            {
                command.CommandText = """
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema = 'security_cache' AND table_name = @table
                    ORDER BY column_name
                    """;
                command.Parameters.AddWithValue("@table", table);
                await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
                while (await reader.ReadAsync(TestContext.Current.CancellationToken))
                {
                    actual.Add(reader.GetString(0));
                }
            }

            actual.Should().BeEquivalentTo(columns, $"table {table} must keep its pinned columns");
        }
    }

    [Fact(DisplayName = "CONTRACT: unique constraints exist on the logical primary keys")]
    public async Task Schema_HasUniqueConstraints()
    {
        var connectionString = _fixture.ConnectionString;
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT tc.table_name, kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name
             AND tc.constraint_schema = kcu.constraint_schema
            WHERE tc.constraint_type = 'PRIMARY KEY'
              AND tc.table_schema = 'security_cache'
            """;
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);

        var keys = new Dictionary<string, string>();
        while (await reader.ReadAsync(TestContext.Current.CancellationToken))
        {
            keys[reader.GetString(0)] = reader.GetString(1);
        }

        keys["jti_replay_cache"].Should().Be("id");
        keys["dpop_nonce_store"].Should().Be("id");
        keys["session_blacklist"].Should().Be("id");
    }
}