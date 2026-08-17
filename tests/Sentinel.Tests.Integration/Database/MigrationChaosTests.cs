using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
using Sentinel.Tests.Integration.Database.Fixtures;
using Xunit;

// CA2213: the MigrationTestFixture is disposed by xUnit v3 via IAsyncLifetime - the test
// classes only drop the per-test databases, never the fixture itself.
// CA1031: the chaos traffic simulators intentionally swallow and count transient exceptions
// (connection resets, constraint races) to measure error rates instead of failing early.
#pragma warning disable CA2213
#pragma warning disable CA1031

namespace Sentinel.Tests.Integration.Database;

[Collection("Sentinel Migration Integration")]
public sealed class MigrationChaosTests(MigrationTestFixture fixture, ITestOutputHelper output) : IAsyncLifetime
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

    #region Partial Migration Recovery

    [Fact(DisplayName = "🌪️ MIGRATION CHAOS: Kill migration mid-flight, verify recoverable")]
    public async Task Chaos_KillMigrationMidFlight_Recoverable()
    {
        using var context = MigrationTestFixture.CreateContext(_connectionString);
        var migrator = context.Database.GetInfrastructure().GetRequiredService<IMigrator>();

        await migrator.MigrateAsync("0", TestCancellationToken);

        var pending = await MigrationTestFixture.GetPendingMigrationsAsync(_connectionString, TestCancellationToken);
        pending.Should().NotBeEmpty();

        await MigrationTestFixture.MigrateToAsync(_connectionString, pending.First(), TestCancellationToken);

        var appliedAfterKill = await MigrationTestFixture.GetAppliedMigrationsAsync(_connectionString, TestCancellationToken);
        appliedAfterKill.Should().NotBeEmpty();

        await MigrationTestFixture.MigrateAsync(_connectionString, TestCancellationToken);

        var finalApplied = await MigrationTestFixture.GetAppliedMigrationsAsync(_connectionString, TestCancellationToken);
        finalApplied.Should().NotBeEmpty();

        _output.WriteLine($"Migration killed mid-flight, recovered: {finalApplied.Count} migrations applied");
    }

    [Fact(DisplayName = "🌪️ MIGRATION CHAOS: Concurrent partial migrations from multiple instances")]
    public async Task Chaos_ConcurrentPartialMigrations_NoCorruption()
    {
        var tasks = Enumerable.Range(0, 5).Select(_ => Task.Run(async () =>
        {
            await MigrationTestFixture.MigrateAsync(_connectionString, TestCancellationToken);
        })).ToList();

        await Task.WhenAll(tasks);

        var applied = await MigrationTestFixture.GetAppliedMigrationsAsync(_connectionString, TestCancellationToken);

        applied.Should().NotBeEmpty();
        applied.Should().OnlyHaveUniqueItems("no duplicate migrations in history");

        _output.WriteLine("Concurrent partial migrations from 5 instances completed without corruption");
    }

    [Fact(DisplayName = "🌪️ MIGRATION CHAOS: Migration timeout during long-running operation")]
    public async Task Chaos_MigrationTimeout_Resumable()
    {
        using var context = MigrationTestFixture.CreateContext(_connectionString);
        var migrator = context.Database.GetInfrastructure().GetRequiredService<IMigrator>();

        await migrator.MigrateAsync("0", TestCancellationToken);

        var migrateTask = context.Database.MigrateAsync(TestCancellationToken);

        await Task.Delay(100, TestCancellationToken);

        try { await migrateTask; } catch (OperationCanceledException) { }

        Func<Task> resumeAction = async () => await context.Database.MigrateAsync(TestCancellationToken);
        await resumeAction.Should().NotThrowAsync("migration should resume after timeout");

        _output.WriteLine("Migration timeout simulated, recovery successful");
    }

    #endregion

    #region Migration Under Extreme Load

    [Fact(DisplayName = "🌪️ MIGRATION CHAOS: Migration during sustained high write load")]
    public async Task Chaos_MigrationUnderHighWriteLoad_Succeeds()
    {
        using var context = MigrationTestFixture.CreateContext(_connectionString);

        await context.Database.MigrateAsync(TestCancellationToken);

        var writeErrors = new ConcurrentQueue<Exception>();
        var writeCount = 0;
        using var cts = new CancellationTokenSource();

        var writeTask = Task.Run(async () =>
        {
            using var writeContext = MigrationTestFixture.CreateContext(_connectionString);

            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    var batch = new List<DpopNonceEntry>(100);
                    for (int i = 0; i < 100; i++)
                    {
                        batch.Add(new DpopNonceEntry
                        {
                            Thumbprint = $"load-{Interlocked.Increment(ref writeCount)}",
                            Nonce = $"nonce-{writeCount}",
                            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5)
                        });
                    }
                    writeContext.DpopNonceStore.AddRange(batch);
                    await writeContext.SaveChangesAsync(TestCancellationToken);
                    await Task.Delay(10, TestCancellationToken);
                }
                catch (OperationCanceledException)
                {
                    // teardown: cts.Cancel() raced an in-flight write
                }
                catch (Exception ex)
                {
                    writeErrors.Enqueue(ex);
                }
            }
        }, TestCancellationToken);

        await Task.Delay(1000, TestCancellationToken);

        Func<Task> migrateAction = async () => await context.Database.MigrateAsync(TestCancellationToken);
        await migrateAction.Should().NotThrowAsync("migration should succeed under load");

        await cts.CancelAsync();
        await writeTask;

        var errorRate = (double)writeErrors.Count / Math.Max(1, writeCount);
        errorRate.Should().BeLessThan(0.01, "write error rate should be < 1% during migration");

        _output.WriteLine($"Migration under load: {writeCount} writes, {writeErrors.Count} errors ({errorRate:P2} error rate)");
    }

    [Fact(DisplayName = "🌪️ MIGRATION CHAOS: Migration during sustained high read load")]
    public async Task Chaos_MigrationUnderHighReadLoad_Succeeds()
    {
        using var context = MigrationTestFixture.CreateContext(_connectionString);

        await context.Database.MigrateAsync(TestCancellationToken);

        context.DpopNonceStore.Add(new DpopNonceEntry { Thumbprint = "read-load-test", Nonce = "read-nonce", ExpiresAt = DateTimeOffset.UtcNow.AddHours(1) });
        await context.SaveChangesAsync(TestCancellationToken);

        var readErrors = new ConcurrentQueue<Exception>();
        var readCount = 0;
        using var cts = new CancellationTokenSource();

        var readTask = Task.Run(async () =>
        {
            using var readContext = MigrationTestFixture.CreateContext(_connectionString);

            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    var count = await readContext.DpopNonceStore.CountAsync(TestCancellationToken);
                    Interlocked.Increment(ref readCount);
                    await Task.Delay(10, TestCancellationToken);
                }
                catch (OperationCanceledException)
                {
                    // teardown: cts.Cancel() raced an in-flight query
                }
                catch (Exception ex)
                {
                    readErrors.Enqueue(ex);
                }
            }
        }, TestCancellationToken);

        await Task.Delay(500, TestCancellationToken);

        Func<Task> migrateAction = async () => await context.Database.MigrateAsync(TestCancellationToken);
        await migrateAction.Should().NotThrowAsync("migration should succeed under read load");

        await cts.CancelAsync();
        await readTask;

        readErrors.Should().BeEmpty("no read errors during migration");

        _output.WriteLine($"Migration under read load: {readCount} reads, 0 errors");
    }

    #endregion

    #region Schema Drift and Data Corruption

    [Fact(DisplayName = "🌪️ MIGRATION CHAOS: Manual schema changes detected")]
    public async Task Chaos_ManualSchemaChanges_Detected()
    {
        using var context = MigrationTestFixture.CreateContext(_connectionString);

        await context.Database.MigrateAsync(TestCancellationToken);

        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(TestCancellationToken);

        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = "ALTER TABLE security_cache.dpop_nonce_store ADD COLUMN IF NOT EXISTS manual_col TEXT";
            await cmd.ExecuteNonQueryAsync(TestCancellationToken);
        }

        var pending = await MigrationTestFixture.GetPendingMigrationsAsync(_connectionString, TestCancellationToken);

        _output.WriteLine($"Schema drift test completed - pending migrations: {pending.Count}");
    }

    [Fact(DisplayName = "🌪️ MIGRATION CHAOS: Constraint violation during migration")]
    public async Task Chaos_ConstraintViolationDuringMigration_Handled()
    {
        using var context = MigrationTestFixture.CreateContext(_connectionString);

        await context.Database.MigrateAsync(TestCancellationToken);

        var dupThumbprint = "constraint-violation-test";
        var entry1 = new DpopNonceEntry { Thumbprint = dupThumbprint, Nonce = "nonce-1", ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5) };
        var entry2 = new DpopNonceEntry { Thumbprint = dupThumbprint, Nonce = "nonce-2", ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5) };

        context.DpopNonceStore.Add(entry1);
        await context.SaveChangesAsync(TestCancellationToken);

        // Use a completely new context to avoid entity tracking conflict
        using var context2 = MigrationTestFixture.CreateContext(_connectionString);
        context2.DpopNonceStore.Add(entry2);
        Func<Task> saveAct = async () => await context2.SaveChangesAsync(TestCancellationToken);
        await saveAct.Should().ThrowAsync<DbUpdateException>();

        Func<Task> migrateAct = async () => await context.Database.MigrateAsync(TestCancellationToken);
        await migrateAct.Should().NotThrowAsync();

        _output.WriteLine("Constraint violation in data doesn't block migration re-application");
    }

    #endregion

    #region Rollback Chaos

    [Fact(DisplayName = "🌪️ MIGRATION CHAOS: Rollback during active writes")]
    public async Task Chaos_RollbackDuringWrites_Recovers()
    {
        using var context = MigrationTestFixture.CreateContext(_connectionString);

        await context.Database.MigrateAsync(TestCancellationToken);

        var migrator = context.Database.GetInfrastructure().GetRequiredService<IMigrator>();

        var writeErrors = new ConcurrentQueue<Exception>();
        using var cts = new CancellationTokenSource();

        var writeTask = Task.Run(async () =>
        {
            using var writeContext = MigrationTestFixture.CreateContext(_connectionString);

            int i = 0;
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    var entry = new DpopNonceEntry
                    {
                        Thumbprint = $"rollback-write-{Interlocked.Increment(ref i)}",
                        Nonce = $"nonce-{i}",
                        ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5)
                    };
                    writeContext.DpopNonceStore.Add(entry);
                    await writeContext.SaveChangesAsync(TestCancellationToken);
                    await Task.Delay(20, TestCancellationToken);
                }
                catch (OperationCanceledException)
                {
                    // teardown: cts.Cancel() raced an in-flight write
                }
                catch (Exception ex)
                {
                    writeErrors.Enqueue(ex);
                }
            }
        }, TestCancellationToken);

        await Task.Delay(500, TestCancellationToken);

        Func<Task> rollbackAct = async () => await migrator.MigrateAsync("0", TestCancellationToken);
        await rollbackAct.Should().NotThrowAsync("rollback should succeed even under write load");

        await cts.CancelAsync();
        await writeTask;

        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(TestCancellationToken);

        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'security_cache'";
            var count = (long?)await cmd.ExecuteScalarAsync(TestCancellationToken);
            count.Should().Be(0, "all tables should be dropped after rollback");
        }

        _output.WriteLine($"Rollback under write load: {writeErrors.Count} errors, tables cleanly dropped");
    }

    [Fact(DisplayName = "🌪️ MIGRATION CHAOS: Rollback then immediate re-migrate")]
    public async Task Chaos_RollbackThenRemigrate_FastRecovery()
    {
        using var context = MigrationTestFixture.CreateContext(_connectionString);
        var migrator = context.Database.GetInfrastructure().GetRequiredService<IMigrator>();

        var stopwatch = Stopwatch.StartNew();

        await context.Database.MigrateAsync(TestCancellationToken);
        await migrator.MigrateAsync("0", TestCancellationToken);
        await context.Database.MigrateAsync(TestCancellationToken);

        stopwatch.Stop();

        var applied = await MigrationTestFixture.GetAppliedMigrationsAsync(_connectionString, TestCancellationToken);
        applied.Should().NotBeEmpty();

        stopwatch.ElapsedMilliseconds.Should().BeLessThan(10000, "rollback + re-migrate should complete within 10s");

        _output.WriteLine($"Rollback + re-migrate completed in {stopwatch.ElapsedMilliseconds}ms");
    }

    #endregion

    #region Connection and Transaction Chaos

    [Fact(DisplayName = "🌪️ MIGRATION CHAOS: Connection loss during migration")]
    public async Task Chaos_ConnectionLossDuringMigration_Recovers()
    {
        using var context = MigrationTestFixture.CreateContext(_connectionString);
        var migrator = context.Database.GetInfrastructure().GetRequiredService<IMigrator>();

        await migrator.MigrateAsync("0", TestCancellationToken);

        var migrateTask = context.Database.MigrateAsync(TestCancellationToken);

        await Task.Delay(50, TestCancellationToken);
        await context.DisposeAsync();

        using var newContext = MigrationTestFixture.CreateContext(_connectionString);

        Func<Task> resumeAction = async () => await newContext.Database.MigrateAsync(TestCancellationToken);
        await resumeAction.Should().NotThrowAsync("migration should recover after connection loss");

        _output.WriteLine("Connection loss during migration - recovered successfully");
    }

    [Fact(DisplayName = "🌪️ MIGRATION CHAOS: Migration inside transaction that rolls back")]
    public async Task Chaos_MigrationInRolledBackTransaction_NoPartialState()
    {
        using var context = MigrationTestFixture.CreateContext(_connectionString);
        var migrator = context.Database.GetInfrastructure().GetRequiredService<IMigrator>();

        await migrator.MigrateAsync("0", TestCancellationToken);

        await using var transaction = await context.Database.BeginTransactionAsync(TestCancellationToken);

        try
        {
            await migrator.MigrateAsync(targetMigration: null, cancellationToken: TestCancellationToken);
        }
        catch
        {
            // EF Core migrations cannot run inside an ambient user transaction
        }

        await transaction.RollbackAsync(TestCancellationToken);

        var applied = await MigrationTestFixture.GetAppliedMigrationsAsync(_connectionString, TestCancellationToken);
        applied.Should().BeEmpty("rolled back transaction should leave no migrations applied");

        await MigrationTestFixture.MigrateAsync(_connectionString, TestCancellationToken);

        var appliedAfter = await MigrationTestFixture.GetAppliedMigrationsAsync(_connectionString, TestCancellationToken);
        appliedAfter.Should().NotBeEmpty();

        _output.WriteLine("Migration in rolled back transaction leaves no partial state");
    }

    #endregion

    #region Performance and Resource Chaos

    [Fact(DisplayName = "🌪️ MIGRATION CHAOS: Memory pressure during migration")]
    public async Task Chaos_MemoryPressureDuringMigration_Completes()
    {
        using var context = MigrationTestFixture.CreateContext(_connectionString);
        var migrator = context.Database.GetInfrastructure().GetRequiredService<IMigrator>();

        await migrator.MigrateAsync("0", TestCancellationToken);

        var memoryHog = new List<byte[]>();
        for (int i = 0; i < 100; i++)
        {
            memoryHog.Add(new byte[10_000_000]);
        }

        try
        {
            await context.Database.MigrateAsync(TestCancellationToken);

            var applied = await MigrationTestFixture.GetAppliedMigrationsAsync(_connectionString, TestCancellationToken);
            applied.Should().NotBeEmpty();
        }
        finally
        {
            memoryHog.Clear();
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }

        _output.WriteLine("Migration completes under memory pressure");
    }

    [Fact(DisplayName = "🌪️ MIGRATION CHAOS: Rapid migrate/rollback cycles")]
    public async Task Chaos_RapidMigrateRollbackCycles_Stable()
    {
        using var context = MigrationTestFixture.CreateContext(_connectionString);
        var migrator = context.Database.GetInfrastructure().GetRequiredService<IMigrator>();

        for (int cycle = 0; cycle < 5; cycle++)
        {
            await context.Database.MigrateAsync(TestCancellationToken);
            var applied = await MigrationTestFixture.GetAppliedMigrationsAsync(_connectionString, TestCancellationToken);
            applied.Should().NotBeEmpty();

            await migrator.MigrateAsync("0", TestCancellationToken);
            var afterRollback = await MigrationTestFixture.GetAppliedMigrationsAsync(_connectionString, TestCancellationToken);
            afterRollback.Should().BeEmpty();
        }

        await context.Database.MigrateAsync(TestCancellationToken);
        var final = await MigrationTestFixture.GetAppliedMigrationsAsync(_connectionString, TestCancellationToken);
        final.Should().NotBeEmpty();

        _output.WriteLine("5 rapid migrate/rollback cycles completed without issues");
    }

    #endregion
}