using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Sentinel.Infrastructure.Persistence;

namespace Sentinel.Infrastructure.Persistence;

/// <summary>
///     Design-time factory for SentinelDbContext (Domain schema).
/// </summary>
public sealed class DesignTimeDomainDbContextFactory : IDesignTimeDbContextFactory<SentinelDbContext>
{
    public SentinelDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<SentinelDbContext>();

        optionsBuilder.UseNpgsql("Host=localhost;Database=sentinel_domain_design_db;Username=postgres;Password=postgres");

        return new SentinelDbContext(optionsBuilder.Options);
    }
}
