using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Sentinel.Domain.Documents;

namespace Sentinel.Persistence.Core.Configurations;

internal sealed class DocumentConfiguration : IEntityTypeConfiguration<Document>
{
    public void Configure(EntityTypeBuilder<Document> builder)
    {
        builder.ToTable("Documents");

        builder.HasKey(document => document.Id);

        builder.Property(document => document.Id)
            .ValueGeneratedNever();

        builder.Property(document => document.OwnerSub)
            .IsRequired()
            .HasMaxLength(256)
            .IsUnicode(false);

        builder.Property(document => document.Title)
            .IsRequired()
            .HasMaxLength(200);

        builder.Property(document => document.Content)
            .IsRequired()
            .HasMaxLength(1_048_576);

        builder.Property(document => document.CreatedAtUtc)
            .IsRequired();

        builder.Property(document => document.UpdatedAtUtc)
            .IsRequired();

        builder.Property(document => document.IsDeleted)
            .IsRequired()
            .HasDefaultValue(false);

        builder.Property(document => document.DeletedAtUtc)
            .IsRequired(false);

        builder.Property(document => document.RowVersion)
            .IsRequired()
            .IsConcurrencyToken();

        builder.HasIndex(document => new { document.OwnerSub, document.IsDeleted, document.UpdatedAtUtc })
            .HasDatabaseName("IX_Documents_Owner_Active");

        builder.HasIndex(document => document.Title)
            .HasDatabaseName("IX_Documents_Title");
    }
}
