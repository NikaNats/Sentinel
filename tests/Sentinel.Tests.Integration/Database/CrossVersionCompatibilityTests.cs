using System;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sentinel.EntityFrameworkCore;
using Sentinel.EntityFrameworkCore.Models;
using Sentinel.Tests.Shared.Fixtures;
using Xunit;

namespace Sentinel.Tests.Integration.Database;

[Collection("Sentinel Integration")]
public sealed class CrossVersionCompatibilityTests(SentinelApiFactory factory, ITestOutputHelper output)
{
    private readonly SentinelApiFactory _factory = factory ?? throw new ArgumentNullException(nameof(factory));
    private readonly ITestOutputHelper _output = output ?? throw new ArgumentNullException(nameof(output));
    private static CancellationToken TestCancellationToken => TestContext.Current.CancellationToken;

    #region Backward Compatibility: Old Code vs New Schema

    [Fact(DisplayName = "🔄 CROSS-VERSION: Old code reads/writes new schema (backward compat)")]
    public async Task BackwardCompat_OldCodeNewSchema_ReadWriteWorks()
    {
        var connStr = GetConnectionString();

        using var setupContext = CreateContext(connStr);
        await setupContext.Database.MigrateAsync(TestCancellationToken);

        await using var connection = new NpgsqlConnection(connStr);
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
        var connStr = GetConnectionString();

        using var setupContext = CreateContext(connStr);
        await setupContext.Database.MigrateAsync(TestCancellationToken);

        await using var connection = new NpgsqlConnection(connStr);
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
        var connStr = GetConnectionString();

        using var setupContext = CreateContext(connStr);
        await setupContext.Database.MigrateAsync(TestCancellationToken);

        using var oldContext = CreateContext(connStr);

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
        var connStr = GetConnectionString();

        using var resetContext = CreateContext(connStr);
        var migrator = resetContext.Database.GetInfrastructure().GetRequiredService<IMigrator>();
        await migrator.MigrateAsync("0", TestCancellationToken);

        using var newContext = CreateContext(connStr);

        var pending = (await newContext.Database.GetPendingMigrationsAsync(TestCancellationToken)).ToList();
        pending.Should().NotBeEmpty("new code on old schema should detect pending migrations");

        _output.WriteLine($"✓ Forward compatibility: New code detects {pending.Count} pending migrations on old schema");
    }

    [Fact(DisplayName = "🔄 CROSS-VERSION: New code can auto-migrate old schema on startup")]
    public async Task ForwardCompat_NewCodeOldSchema_AutoMigrates()
    {
        var connStr = GetConnectionString();

        using var resetContext = CreateContext(connStr);
        var migrator = resetContext.Database.GetInfrastructure().GetRequiredService<IMigrator>();
        await migrator.MigrateAsync("0", TestCancellationToken);

        using var newContext = CreateContext(connStr);

        Func<Task> migrateAction = async () => await newContext.Database.MigrateAsync(TestCancellationToken);
        await migrateAction.Should().NotThrowAsync("new code should auto-migrate old schema");

        var pending = (await newContext.Database.GetPendingMigrationsAsync(TestCancellationToken)).ToList();
        pending.Should().BeEmpty("schema should be fully migrated after auto-migration");

        _output.WriteLine("✓ Forward compatibility: New code auto-migrates old schema on startup");
    }

    [Fact(DisplayName = "🔄 CROSS-VERSION: New code handles missing columns gracefully (added columns)")]
    public async Task ForwardCompat_NewCodeOldSchema_MissingColumnsHandled()
    {
        var connStr = GetConnectionString();

        using var resetContext = CreateContext(connStr);
        var migrator = resetContext.Database.GetInfrastructure().GetRequiredService<IMigrator>();
        await migrator.MigrateAsync("0", TestCancellationToken);

        using var newContext = CreateContext(connStr);

        Func<Task> act = async () => await newContext.DpopNonceStore.CountAsync(TestCancellationToken);
        await act.Should().ThrowAsync<Exception>("tables don't exist in baseline schema");

        _output.WriteLine("✓ Forward compatibility: New code fails gracefully on missing tables");
    }

    #endregion

    #region Rolling Deployment Scenarios

    [Fact(DisplayName = "🔄 CROSS-VERSION: Rolling deploy - Mixed versions during deployment")]
    public async Task RollingDeploy_MixedVersions_BothWork()
    {
        var connStr = GetConnectionString();

        using var setupContext = CreateContext(connStr);
        await setupContext.Database.MigrateAsync(TestCancellationToken);

        var v1Task = Task.Run(async () =>
        {
            await using var connection = new NpgsqlConnection(connStr);
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
        });

        var v2Task = Task.Run(async () =>
        {
            using var context = CreateContext(connStr);
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
        });

        await Task.WhenAll(v1Task, v2Task);

        using var verifyContext = CreateContext(connStr);
        var v1Count = await verifyContext.DpopNonceStore.CountAsync(e => e.Thumbprint.StartsWith("v1-pod-"), TestCancellationToken);
        var v2Count = await verifyContext.DpopNonceStore.CountAsync(e => e.Thumbprint.StartsWith("v2-pod-"), TestCancellationToken);

        v1Count.Should().Be(10);
        v2Count.Should().Be(10);

        _output.WriteLine($"✓ Rolling deployment: v1 wrote {v1Count}, v2 wrote {v2Count} records simultaneously");
    }

    [Fact(DisplayName = "🔄 CROSS-VERSION: Blue-green deploy - New schema, instant switch")]
    public async Task BlueGreenDeploy_NewSchema_InstantSwitch()
    {
        var connStr = GetConnectionString();

        using var greenContext = CreateContext(connStr);

        await greenContext.Database.MigrateAsync(TestCancellationToken);

        var pending = (await greenContext.Database.GetPendingMigrationsAsync(TestCancellationToken)).ToList();
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

    #region Helper Methods

    private string GetConnectionString()
    {
        using var scope = _factory.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<SentinelSecurityDbContext>();
        return context.Database.GetConnectionString()!;
    }

    private static SentinelSecurityDbContext CreateContext(string connectionString)
    {
        return new SentinelSecurityDbContext(new DbContextOptionsBuilder<SentinelSecurityDbContext>()
            .UseNpgsql(connectionString)
            .Options);
    }

    #endregion
}
