using Microsoft.EntityFrameworkCore;
using Sentinel.Domain.Documents;

namespace Sentinel.Persistence.Core;

public abstract class SentinelDbContext(DbContextOptions options) : DbContext(options)
{
    public DbSet<Document> Documents => Set<Document>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.ApplyConfigurationsFromAssembly(typeof(SentinelDbContext).Assembly);

        if (GetType().Assembly != typeof(SentinelDbContext).Assembly)
        {
            builder.ApplyConfigurationsFromAssembly(GetType().Assembly);
        }

        builder.Entity<Document>().HasQueryFilter(document => !document.IsDeleted);
    }
}
