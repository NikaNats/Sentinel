using Microsoft.EntityFrameworkCore;

namespace Sentinel.Infrastructure.Persistence;

public sealed class SentinelDbContext(DbContextOptions<SentinelDbContext> options) : DbContext(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Framework-only entities registration
        // Domain-specific entities have been moved to Sentinel.SampleHost
    }
}
