using Sentinel.Application.Models;

namespace Sentinel.Application.Common.Abstractions;

public interface IDocumentStore
{
    Task<PagedResult<DocumentDto>> ListAsync(string ownerSub, DocumentQuery query, CancellationToken cancellationToken);
    Task<DocumentDto?> GetByIdAsync(Guid id, string ownerSub, CancellationToken cancellationToken);
    Task<DocumentDto> CreateAsync(string ownerSub, CreateDocumentRequest request, CancellationToken cancellationToken);
    Task<DocumentDto?> UpdateAsync(Guid id, string ownerSub, UpdateDocumentRequest request, string rowVersion, CancellationToken cancellationToken);
    Task<bool> DeleteAsync(Guid id, string ownerSub, CancellationToken cancellationToken);
}

public sealed record DocumentQuery(
    int Page = 1,
    int PageSize = 20,
    string? SearchTerm = null,
    DocumentSortBy SortBy = DocumentSortBy.UpdatedAtDesc);

public enum DocumentSortBy
{
    UpdatedAtDesc,
    UpdatedAtAsc,
    TitleAsc,
    TitleDesc,
    CreatedAtDesc
}

public sealed record PagedResult<T>(
    IReadOnlyList<T> Items,
    int TotalCount,
    int Page,
    int PageSize)
{
    public int TotalPages => PageSize <= 0 ? 0 : (int)Math.Ceiling(TotalCount / (double)PageSize);

    public bool HasNextPage => Page < TotalPages;

    public bool HasPrevPage => Page > 1;
}
