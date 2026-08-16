using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sentinel.EntityFrameworkCore;
using Sentinel.EntityFrameworkCore.Models;
using Testcontainers.PostgreSql;

namespace Sentinel.Tests.Integration.Database.Fixtures;

/// <summary>
/// Fixture for comprehensive migration testing with support for:
/// - Multiple database versions
/// - Cross-version compatibility testing
/// - Partial migration simulation
/// - Concurrent migration scenarios
/// </summary>
public sealed class MigrationTestFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgres;
    private string _connectionString = string.Empty;

    public MigrationTestFixture()
    {
        _postgres = new PostgreSqlBuilder()
            .WithImage("postgres:17-alpine")
            .WithDatabase("sentinel_migration_test")
            .WithUsername("migration_user")
            .WithPassword("migration_password")
            .Build();
    }

    public string ConnectionString => _connectionString;

    public async ValueTask InitializeAsync()
    {
        await _postgres.StartAsync();
        _connectionString = _postgres.GetConnectionString();
    }

    public async ValueTask DisposeAsync()
    {
        await _postgres.DisposeAsync();
    }

    /// <summary>
    /// Creates a fresh database for isolated testing
    /// </summary>
    public async Task<string> CreateFreshDatabaseAsync(string? name = null)
    {
        var dbName = name ?? $"migration_test_{Guid.NewGuid():N}";
        var adminBuilder = new NpgsqlConnectionStringBuilder(_postgres.GetConnectionString())
        {
            Database = "postgres"
        };

        await using var connection = new NpgsqlConnection(adminBuilder.ToString());
        await connection.OpenAsync();

        await using var command = connection.CreateCommand();
        command.CommandText = $"CREATE DATABASE \"{dbName}\" TEMPLATE template0 ENCODING 'UTF8'";
        try
        {
            await command.ExecuteNonQueryAsync();
        }
        catch (PostgresException ex) when (ex.SqlState == "42P04")
        {
            // Database already exists
        }

        var builder = new NpgsqlConnectionStringBuilder(_postgres.GetConnectionString())
        {
            Database = dbName
        };
        return builder.ToString();
    }

    /// <summary>
    /// Creates a SentinelSecurityDbContext for the given connection string
    /// </summary>
    public static SentinelSecurityDbContext CreateContext(string connectionString)
    {
        return new SentinelSecurityDbContext(new DbContextOptionsBuilder<SentinelSecurityDbContext>()
            .UseNpgsql(connectionString)
            .Options);
    }

    /// <summary>
    /// Applies all migrations to the database
    /// </summary>
    public static async Task MigrateAsync(string connectionString, CancellationToken ct = default)
    {
        using var context = CreateContext(connectionString);
        await context.Database.MigrateAsync(ct);
    }

    /// <summary>
    /// Rolls back all migrations to baseline (0)
    /// </summary>
    public static async Task RollbackToBaselineAsync(string connectionString, CancellationToken ct = default)
    {
        using var context = CreateContext(connectionString);
        var migrator = context.Database.GetInfrastructure().GetRequiredService<IMigrator>();
        await migrator.MigrateAsync("0", ct);
    }

    /// <summary>
    /// Applies migrations up to a specific migration
    /// </summary>
    public static async Task MigrateToAsync(string connectionString, string targetMigration, CancellationToken ct = default)
    {
        using var context = CreateContext(connectionString);
        var migrator = context.Database.GetInfrastructure().GetRequiredService<IMigrator>();
        await migrator.MigrateAsync(targetMigration, ct);
    }

    /// <summary>
    /// Gets the list of applied migrations
    /// </summary>
    public static async Task<List<string>> GetAppliedMigrationsAsync(string connectionString, CancellationToken ct = default)
    {
        using var context = CreateContext(connectionString);
        return (await context.Database.GetAppliedMigrationsAsync(ct)).ToList();
    }

    /// <summary>
    /// Gets pending migrations
    /// </summary>
    public static async Task<List<string>> GetPendingMigrationsAsync(string connectionString, CancellationToken ct = default)
    {
        using var context = CreateContext(connectionString);
        return (await context.Database.GetPendingMigrationsAsync(ct)).ToList();
    }

    /// <summary>
    /// Verifies database schema matches model (no pending changes)
    /// </summary>
    public static async Task<bool> VerifySchemaMatchesModelAsync(string connectionString, CancellationToken ct = default)
    {
        using var context = CreateContext(connectionString);
        var pending = await context.Database.GetPendingMigrationsAsync(ct);
        return !pending.Any();
    }

    /// <summary>
    /// Generates the SQL script for pending migrations
    /// </summary>
    public static async Task<string> GenerateMigrationScriptAsync(string connectionString, CancellationToken ct = default)
    {
        using var context = CreateContext(connectionString);
        var pendingMigrations = (await context.Database.GetPendingMigrationsAsync(ct)).ToList();

        if (!pendingMigrations.Any())
        {
            return string.Empty;
        }

        // Placeholder - actual script generation requires complex EF Core internals
        // In practice, use 'dotnet ef migrations script' CLI command for script generation
        return $"-- Migration script for {pendingMigrations.Count} pending migrations\n-- Use 'dotnet ef migrations script' for full script";
    }

    /// <summary>
    /// Seeds test data into the database
    /// </summary>
    public static async Task SeedTestDataAsync(string connectionString, int count = 100, CancellationToken ct = default)
    {
        using var context = CreateContext(connectionString);

        var entries = new List<DpopNonceEntry>(count);
        for (int i = 0; i < count; i++)
        {
            entries.Add(new DpopNonceEntry
            {
                Thumbprint = $"seed-{i}",
                Nonce = $"nonce-{i}",
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1)
            });
        }

        context.DpopNonceStore.AddRange(entries);
        await context.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Gets table row counts
    /// </summary>
    public static async Task<Dictionary<string, long>> GetTableCountsAsync(string connectionString, CancellationToken ct = default)
    {
        using var context = CreateContext(connectionString);
        return new Dictionary<string, long>
        {
            ["dpop_nonce_store"] = await context.DpopNonceStore.LongCountAsync(ct),
            ["jti_replay_cache"] = await context.JtiReplayCache.LongCountAsync(ct),
            ["session_blacklist"] = await context.SessionBlacklist.LongCountAsync(ct)
        };
    }
}

/// <summary>
/// Fixture for cross-version compatibility testing
/// Allows testing old code against new schema and new code against old schema
/// </summary>
public sealed class CrossVersionMigrationFixture : IAsyncLifetime
{
    private readonly MigrationTestFixture _migrationFixture;

    public CrossVersionMigrationFixture()
    {
        _migrationFixture = new MigrationTestFixture();
    }

    public string ConnectionString => _migrationFixture.ConnectionString;

    public async ValueTask InitializeAsync()
    {
        await _migrationFixture.InitializeAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await _migrationFixture.DisposeAsync();
    }

    /// <summary>
    /// Creates a database at a specific migration version for testing compatibility
    /// </summary>
    public async Task<string> CreateDatabaseAtVersionAsync(string targetMigration, string? dbName = null)
    {
        var connStr = await _migrationFixture.CreateFreshDatabaseAsync(dbName);
        await MigrationTestFixture.MigrateToAsync(connStr, targetMigration);
        return connStr;
    }

    /// <summary>
    /// Creates a database with the latest schema (simulating production)
    /// </summary>
    public async Task<string> CreateLatestSchemaDatabaseAsync(string? dbName = null)
    {
        var connStr = await _migrationFixture.CreateFreshDatabaseAsync(dbName);
        await MigrationTestFixture.MigrateAsync(connStr);
        return connStr;
    }

    /// <summary>
    /// Creates a database rolled back to baseline (empty)
    /// </summary>
    public async Task<string> CreateBaselineDatabaseAsync(string? dbName = null)
    {
        var connStr = await _migrationFixture.CreateFreshDatabaseAsync(dbName);
        await MigrationTestFixture.RollbackToBaselineAsync(connStr);
        return connStr;
    }
}

/// <summary>
/// Utility for simulating partial migration scenarios
/// </summary>
public static class PartialMigrationSimulator
{
    /// <summary>
    /// Simulates a migration interrupted after N steps
    /// </summary>
    public static async Task<PartialMigrationResult> SimulateInterruptedMigrationAsync(
        string connectionString,
        int stepsToComplete,
        CancellationToken ct = default)
    {
        var result = new PartialMigrationResult();

        using var context = MigrationTestFixture.CreateContext(connectionString);
        var migrator = context.Database.GetInfrastructure().GetRequiredService<IMigrator>();

        await migrator.MigrateAsync("0", ct);

        var pending = (await context.Database.GetPendingMigrationsAsync(ct)).ToList();
        result.TotalSteps = pending.Count;
        result.RequestedSteps = Math.Min(stepsToComplete, pending.Count);

        for (int i = 0; i < result.RequestedSteps && i < pending.Count; i++)
        {
            try
            {
                await migrator.MigrateAsync(pending[i], ct);
                result.CompletedSteps.Add(pending[i]);
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                result.ExceptionType = ex.GetType().Name;
                break;
            }
        }

        var applied = (await context.Database.GetAppliedMigrationsAsync(ct)).ToList();
        result.AppliedMigrations = applied;
        result.IsComplete = result.CompletedSteps.Count == pending.Count;

        return result;
    }

    /// <summary>
    /// Attempts to recover from a partial migration
    /// </summary>
    public static async Task<RecoveryResult> AttemptRecoveryAsync(
        string connectionString,
        CancellationToken ct = default)
    {
        var result = new RecoveryResult();

        try
        {
            using var context = MigrationTestFixture.CreateContext(connectionString);
            var beforeRecovery = (await context.Database.GetAppliedMigrationsAsync(ct)).ToList();
            result.MigrationsBeforeRecovery = beforeRecovery;

            await context.Database.MigrateAsync(ct);

            var afterRecovery = (await context.Database.GetAppliedMigrationsAsync(ct)).ToList();
            result.MigrationsAfterRecovery = afterRecovery;
            result.Success = true;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
            result.ExceptionType = ex.GetType().Name;
        }

        return result;
    }
}

/// <summary>
/// Result of a compatibility test
/// </summary>
public sealed class CompatibilityTestResult
{
    public string Scenario { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string? Error { get; set; }
    public string? ExceptionType { get; set; }
    public int PendingMigrations { get; set; }
}

/// <summary>
/// Result of a partial migration simulation
/// </summary>
public sealed class PartialMigrationResult
{
    public int TotalSteps { get; set; }
    public int RequestedSteps { get; set; }
    public List<string> CompletedSteps { get; set; } = new();
    public List<string> AppliedMigrations { get; set; } = new();
    public bool IsComplete { get; set; }
    public string? Error { get; set; }
    public string? ExceptionType { get; set; }
}

/// <summary>
/// Result of a migration recovery attempt
/// </summary>
public sealed class RecoveryResult
{
    public List<string> MigrationsBeforeRecovery { get; set; } = new();
    public List<string> MigrationsAfterRecovery { get; set; } = new();
    public bool Success { get; set; }
    public string? Error { get; set; }
    public string? ExceptionType { get; set; }
}
