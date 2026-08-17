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
/// - Isolated databases per test (CreateFreshDatabaseAsync)
/// - Forward/rollback migration helpers
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
    /// Drops a database created by <see cref="CreateFreshDatabaseAsync"/>
    /// </summary>
    public async Task DropDatabaseAsync(string connectionString)
    {
        var dbName = new NpgsqlConnectionStringBuilder(connectionString).Database;
        var adminBuilder = new NpgsqlConnectionStringBuilder(_postgres.GetConnectionString())
        {
            Database = "postgres"
        };

        await using var connection = new NpgsqlConnection(adminBuilder.ToString());
        await connection.OpenAsync();

        await using var command = connection.CreateCommand();
        command.CommandText = $"DROP DATABASE IF EXISTS \"{dbName}\" WITH (FORCE)";
        await command.ExecuteNonQueryAsync();
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
