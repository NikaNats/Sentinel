using Microsoft.EntityFrameworkCore;
using Sentinel.SampleHost.Models;

namespace Sentinel.SampleHost;

public sealed class SampleHostDbContext(DbContextOptions<SampleHostDbContext> options) : DbContext(options)
{
    public DbSet<DocumentEntity> Documents => Set<DocumentEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<DocumentEntity>(entity =>
        {
            entity.ToTable("documents");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.OwnerSub).HasColumnName("owner_sub").IsRequired().HasMaxLength(64);
            entity.Property(e => e.Title).HasColumnName("title").IsRequired().HasMaxLength(128);
            entity.Property(e => e.Content).HasColumnName("content").IsRequired().HasMaxLength(4096);
            entity.Property(e => e.CreatedAtUtc).HasColumnName("created_at_utc").IsRequired();
            entity.Property(e => e.UpdatedAtUtc).HasColumnName("updated_at_utc").IsRequired();
            entity.HasIndex(e => e.OwnerSub).HasDatabaseName("ix_documents_owner_sub");
        });
    }
}
