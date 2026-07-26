using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.EntityFrameworkCore;
using Sentinel.EntityFrameworkCore.Models;
using Sentinel.Tests.Shared.Fixtures;
using Xunit;

namespace Sentinel.Tests.Integration.Database;

[Collection("Sentinel Integration")]
public sealed class MigrationResilienceTests(SentinelApiFactory factory)
{
    private readonly SentinelApiFactory _factory = factory ?? throw new ArgumentNullException(nameof(factory));

    private static CancellationToken TestCancellationToken => TestContext.Current.CancellationToken;

    [Fact(DisplayName = "🛡️ DB Migration: Up -> Seed -> Down -> Up cycle must execute flawlessly with no constraint violations")]
    public async Task Verify_SecurityDbContextSchema_CanRollbackAndReapply_Safely()
    {
        // Arrange
        using var scope = _factory.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<SentinelSecurityDbContext>();

        // Use the official public EF Core API to read the list of migrations
        var migrationsList = context.Database.GetMigrations().ToList();
        migrationsList.Should().NotBeEmpty("At least one migration must be registered in the project assembly.");

        // 1. Ensure the database is at the latest migration (UP)
        await context.Database.MigrateAsync(TestCancellationToken);

        // 2. Insert test data for migration verification
        var testThumbprint = "test-verification-thumbprint-hash";
        var testNonce = new DpopNonceEntry
        {
            Thumbprint = testThumbprint,
            Nonce = "active-validation-token-999",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            CreatedAt = DateTimeOffset.UtcNow
        };

        context.DpopNonceStore.Add(testNonce);
        await context.SaveChangesAsync(TestCancellationToken);

        // 3. Run the Down migration to the initial state ("0" means complete cleanup)
        var migrator = context.Database.GetInfrastructure().GetRequiredService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>();
        await migrator.MigrateAsync("0", TestCancellationToken);

        // Verify that the schema was dropped and accessing the tables throws an exception (since the table physically no longer exists)
        var verifyDeletedAct = () => context.DpopNonceStore.AnyAsync(TestCancellationToken);
        await verifyDeletedAct.Should().ThrowAsync<Exception>("The schema and tables must be dropped entirely after rolling back to '0'.");

        // 4. Rebuild the schema up to the latest migration (UP)
        await context.Database.MigrateAsync(TestCancellationToken);

        // Verify that the schema was recreated and the table is accessible (but without data)
        var exists = await context.DpopNonceStore.AnyAsync(TestCancellationToken);
        exists.Should().BeFalse("The table should be empty after a fresh rebuild.");
    }
}
