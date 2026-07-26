using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Sentinel.EntityFrameworkCore;

/// <summary>
///     Design-time factory for SentinelSecurityDbContext.
///     This enables EF Core CLI tools to generate migrations without relying on the startup project's DI container.
/// </summary>
public sealed class DesignTimeSecurityDbContextFactory : IDesignTimeDbContextFactory<SentinelSecurityDbContext>
{
    public SentinelSecurityDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<SentinelSecurityDbContext>();

        // Dummy connection string for design-time simulation.
        // CLI tools only need to analyze the schema structure and do not connect to the real database during code generation.
        optionsBuilder.UseNpgsql("Host=localhost;Database=sentinel_design_db;Username=postgres;Password=postgres");

        return new SentinelSecurityDbContext(optionsBuilder.Options);
    }
}
