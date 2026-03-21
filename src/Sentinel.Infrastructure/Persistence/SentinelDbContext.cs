using Microsoft.EntityFrameworkCore;

namespace Sentinel.Infrastructure.Persistence;

public sealed class SentinelDbContext(DbContextOptions<SentinelDbContext> options) : DbContext(options)
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

public sealed class DocumentEntity
{
    public Guid Id { get; set; }
    public string OwnerSub { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
}
