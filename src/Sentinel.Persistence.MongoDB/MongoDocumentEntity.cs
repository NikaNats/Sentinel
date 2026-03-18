namespace Sentinel.Persistence.MongoDB;

public sealed class MongoDocumentEntity
{
    public Guid Id { get; set; }

    public string OwnerSub { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public string Content { get; set; } = string.Empty;

    public DateTimeOffset CreatedAtUtc { get; set; }

    public DateTimeOffset UpdatedAtUtc { get; set; }

    public bool IsDeleted { get; set; }

    public DateTimeOffset? DeletedAtUtc { get; set; }

    public long Version { get; set; } = 1;
}
