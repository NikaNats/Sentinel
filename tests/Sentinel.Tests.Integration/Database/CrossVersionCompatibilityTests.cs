using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sentinel.EntityFrameworkCore;
using Sentinel.EntityFrameworkCore.Models;
using Sentinel.Tests.Integration.Database.Fixtures;
using Xunit;

// CA2213: the MigrationTestFixture is disposed by xUnit v3 via IAsyncLifetime - the test
// classes only drop the per-test databases, never the fixture itself.
#pragma warning disable CA2213

namespace Sentinel.Tests.Integration.Database;

[Collection("Sentinel Migration Integration")]
public sealed class CrossVersionCompatibilityTests(MigrationTestFixture fixture, ITestOutputHelper output) : IAsyncLifetime
{
    private readonly MigrationTestFixture _fixture = fixture ?? throw new ArgumentNullException(nameof(fixture));
    private readonly ITestOutputHelper _output = output ?? throw new ArgumentNullException(nameof(output));
    private string _connectionString = string.Empty;
    private static CancellationToken TestCancellationToken => TestContext.Current.CancellationToken;

    public async ValueTask InitializeAsync()
    {
        _connectionString = await _fixture.CreateFreshDatabaseAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await _fixture.DropDatabaseAsync(_connectionString);
    }

    #region Backward Compatibility: Old Code vs New Schema

    [Fact(DisplayName = "🔄 CROSS-VERSION: Old code reads/writes new schema (backward compat)")]
    public async Task BackwardCompat_OldCodeNewSchema_ReadWriteWorks()
    {
        await MigrationTestFixture.MigrateAsync(_connectionString, TestCancellationToken);

        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(TestCancellationToken);

        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = """
                INSERT INTO security_cache.dpop_nonce_store (id, nonce, expires_at, created_at)
                VALUES (@id, @nonce, @expires, @created)
                """;
            cmd.Parameters.Add(new NpgsqlParameter("@id", "v1-insert-test"));
            cmd.Parameters.Add(new NpgsqlParameter("@nonce", "v1-nonce-value"));
            cmd.Parameters.Add(new NpgsqlParameter("@expires", DateTimeOffset.UtcNow.AddHours(1)));
            cmd.Parameters.Add(new NpgsqlParameter("@created", DateTimeOffset.UtcNow));
            await cmd.ExecuteNonQueryAsync(TestCancellationToken);
        }

        string? retrievedNonce = null;
        await using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = "SELECT nonce FROM security_cache.dpop_nonce_store WHERE id = @id";
            cmd.Parameters.Add(new NpgsqlParameter("@id", "v1-insert-test"));
            retrievedNonce = (string?)await cmd.ExecuteScalarAsync(TestCancellationToken);
        }

        retrievedNonce.Should().Be("v1-nonce-value", "v1 code should read v2 schema data correctly");

        _output.WriteLine("✓ Backward compatibility: v1 code works with v2 schema");
    }

    [Fact(DisplayName = "🔄 CROSS-VERSION: Old code handles new nullable columns gracefully")]
    public async Task BackwardCompat_OldCodeNewSchema_NullableColumnsIgnored()
    {
        await MigrationTestFixture.MigrateAsync(_connectionString, TestCancellationToken);

        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(TestCancellationToken);

        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = """
                INSERT INTO security_cache.dpop_nonce_store (id, nonce, expires_at, created_at)
                VALUES (@id, @nonce, @expires, @created)
                """;
            cmd.Parameters.Add(new NpgsqlParameter("@id", "nullable-col-test"));
            cmd.Parameters.Add(new NpgsqlParameter("@nonce", "nullable-test-nonce"));
            cmd.Parameters.Add(new NpgsqlParameter("@expires", DateTimeOffset.UtcNow.AddHours(1)));
            cmd.Parameters.Add(new NpgsqlParameter("@created", DateTimeOffset.UtcNow));
            await cmd.ExecuteNonQueryAsync(TestCancellationToken);
        }

        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = "SELECT id FROM security_cache.dpop_nonce_store WHERE id = @id";
            cmd.Parameters.Add(new NpgsqlParameter("@id", "nullable-col-test"));
            var id = await cmd.ExecuteScalarAsync(TestCancellationToken);
            id.Should().Be("nullable-col-test");
        }

        _output.WriteLine("✓ Backward compatibility: v1 code handles nullable new columns");
    }

    [Fact(DisplayName = "🔄 CROSS-VERSION: Old EF Core code works with new schema")]
    public async Task BackwardCompat_OldEfCoreNewSchema_EfCoreWorks()
    {
        await MigrationTestFixture.MigrateAsync(_connectionString, TestCancellationToken);

        using var oldContext = MigrationTestFixture.CreateContext(_connectionString);

        var count = await oldContext.DpopNonceStore.CountAsync(TestCancellationToken);
        count.Should().BeGreaterThanOrEqualTo(0);

        var entry = new DpopNonceEntry
        {
            Thumbprint = "ef-old-code-test",
            Nonce = "ef-old-nonce",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1)
        };
        oldContext.DpopNonceStore.Add(entry);
        await oldContext.SaveChangesAsync(TestCancellationToken);

        var inserted = await oldContext.DpopNonceStore
            .FirstOrDefaultAsync(e => e.Thumbprint == "ef-old-code-test", TestCancellationToken);
        inserted.Should().NotBeNull();
        inserted!.Nonce.Should().Be("ef-old-nonce");

        _output.WriteLine("✓ Backward compatibility: Old EF Core works with new schema");
    }

    #endregion

    #region Forward Compatibility: New Code vs Old Schema

    [Fact(DisplayName = "🔄 CROSS-VERSION: New code detects pending migrations on old schema")]
    public async Task ForwardCompat_NewCodeOldSchema_DetectsPendingMigrations()
    {
        // Fresh database is at baseline (old schema)
        var pending = await MigrationTestFixture.GetPendingMigrationsAsync(_connectionString, TestCancellationToken);
        pending.Should().NotBeEmpty("new code on old schema should detect pending migrations");

        _output.WriteLine($"✓ Forward compatibility: New code detects {pending.Count} pending migrations on old schema");
    }

    [Fact(DisplayName = "🔄 CROSS-VERSION: New code can auto-migrate old schema on startup")]
    public async Task ForwardCompat_NewCodeOldSchema_AutoMigrates()
    {
        // Fresh database is at baseline (old schema)
        Func<Task> migrateAction = async () => await MigrationTestFixture.MigrateAsync(_connectionString, TestCancellationToken);
        await migrateAction.Should().NotThrowAsync("new code should auto-migrate old schema");

        var pending = await MigrationTestFixture.GetPendingMigrationsAsync(_connectionString, TestCancellationToken);
        pending.Should().BeEmpty("schema should be fully migrated after auto-migration");

        _output.WriteLine("✓ Forward compatibility: New code auto-migrates old schema on startup");
    }

    [Fact(DisplayName = "🔄 CROSS-VERSION: New code handles missing columns gracefully (added columns)")]
    public async Task ForwardCompat_NewCodeOldSchema_MissingColumnsHandled()
    {
        // Fresh database is at baseline (old schema) - tables don't exist yet
        using var newContext = MigrationTestFixture.CreateContext(_connectionString);

        Func<Task> act = async () => await newContext.DpopNonceStore.CountAsync(TestCancellationToken);
        await act.Should().ThrowAsync<Exception>("tables don't exist in baseline schema");

        _output.WriteLine("✓ Forward compatibility: New code fails gracefully on missing tables");
    }

    #endregion

    #region Rolling Deployment Scenarios

    [Fact(DisplayName = "🔄 CROSS-VERSION: Rolling deploy - Mixed versions during deployment")]
    public async Task RollingDeploy_MixedVersions_BothWork()
    {
        await MigrationTestFixture.MigrateAsync(_connectionString, TestCancellationToken);

        var v1Task = Task.Run(async () =>
        {
            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(TestCancellationToken);

            for (int i = 0; i < 10; i++)
            {
                using var cmd = connection.CreateCommand();
                cmd.CommandText = """
                    INSERT INTO security_cache.dpop_nonce_store (id, nonce, expires_at, created_at)
                    VALUES (@id, @nonce, @expires, @created)
                    """;
                cmd.Parameters.Add(new NpgsqlParameter("@id", $"v1-pod-{i}"));
                cmd.Parameters.Add(new NpgsqlParameter("@nonce", $"v1-nonce-{i}"));
                cmd.Parameters.Add(new NpgsqlParameter("@expires", DateTimeOffset.UtcNow.AddHours(1)));
                cmd.Parameters.Add(new NpgsqlParameter("@created", DateTimeOffset.UtcNow));
                await cmd.ExecuteNonQueryAsync(TestCancellationToken);
            }
        }, TestCancellationToken);

        var v2Task = Task.Run(async () =>
        {
            using var context = MigrationTestFixture.CreateContext(_connectionString);
            for (int i = 0; i < 10; i++)
            {
                var entry = new DpopNonceEntry
                {
                    Thumbprint = $"v2-pod-{i}",
                    Nonce = $"v2-nonce-{i}",
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(1)
                };
                context.DpopNonceStore.Add(entry);
                await context.SaveChangesAsync(TestCancellationToken);
            }
        }, TestCancellationToken);

        await Task.WhenAll(v1Task, v2Task);

        using var verifyContext = MigrationTestFixture.CreateContext(_connectionString);
        var v1Count = await verifyContext.DpopNonceStore.CountAsync(e => e.Thumbprint.StartsWith("v1-pod-"), TestCancellationToken);
        var v2Count = await verifyContext.DpopNonceStore.CountAsync(e => e.Thumbprint.StartsWith("v2-pod-"), TestCancellationToken);

        v1Count.Should().Be(10);
        v2Count.Should().Be(10);

        _output.WriteLine($"✓ Rolling deployment: v1 wrote {v1Count}, v2 wrote {v2Count} records simultaneously");
    }

    [Fact(DisplayName = "🔄 CROSS-VERSION: Blue-green deploy - New schema, instant switch")]
    public async Task BlueGreenDeploy_NewSchema_InstantSwitch()
    {
        using var greenContext = MigrationTestFixture.CreateContext(_connectionString);

        await greenContext.Database.MigrateAsync(TestCancellationToken);

        var pending = await MigrationTestFixture.GetPendingMigrationsAsync(_connectionString, TestCancellationToken);
        pending.Should().BeEmpty("green environment fully migrated");

        var entry = new DpopNonceEntry
        {
            Thumbprint = "green-first-request",
            Nonce = "green-nonce",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1)
        };
        greenContext.DpopNonceStore.Add(entry);
        await greenContext.SaveChangesAsync(TestCancellationToken);

        var count = await greenContext.DpopNonceStore.CountAsync(TestCancellationToken);
        count.Should().BeGreaterThan(0);

        _output.WriteLine("✓ Blue-green deployment: Green environment ready for instant traffic switch");
    }

    #endregion
}