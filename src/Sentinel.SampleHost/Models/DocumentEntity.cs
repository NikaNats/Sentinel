namespace Sentinel.SampleHost.Models;

public sealed class DocumentEntity
{
    public Guid Id { get; set; }
    public string OwnerSub { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
}
