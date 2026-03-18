namespace Sentinel.Domain.Documents;

/// <summary>
/// Document aggregate root used by pluggable persistence adapters.
/// </summary>
public sealed class Document
{
    private Document()
    {
    }

    public Guid Id { get; private set; }

    public string OwnerSub { get; private set; } = string.Empty;

    public string Title { get; private set; } = string.Empty;

    public string Content { get; private set; } = string.Empty;

    public DateTimeOffset CreatedAtUtc { get; private set; }

    public DateTimeOffset UpdatedAtUtc { get; private set; }

    public byte[] RowVersion { get; private set; } = [];

    public bool IsDeleted { get; private set; }

    public DateTimeOffset? DeletedAtUtc { get; private set; }

    public static Document Create(string ownerSub, string title, string content)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerSub);
        ArgumentException.ThrowIfNullOrWhiteSpace(title);

        DateTimeOffset now = DateTimeOffset.UtcNow;

        return new Document
        {
            Id = Guid.NewGuid(),
            OwnerSub = ownerSub.Trim(),
            Title = title.Trim(),
            Content = content,
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        };
    }

    public void Update(string title, string content)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);

        Title = title.Trim();
        Content = content;
        UpdatedAtUtc = DateTimeOffset.UtcNow;
    }

    public void SoftDelete()
    {
        if (IsDeleted)
        {
            return;
        }

        IsDeleted = true;
        DeletedAtUtc = DateTimeOffset.UtcNow;
        UpdatedAtUtc = DeletedAtUtc.Value;
    }

    public void SetRowVersion(byte[] rowVersion)
    {
        RowVersion = rowVersion.Length == 0 ? [] : rowVersion.ToArray();
    }

    public bool BelongsTo(string sub) =>
        string.Equals(OwnerSub, sub, StringComparison.Ordinal);
}
