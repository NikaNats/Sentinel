using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Application.Models;
using Sentinel.Domain.Documents;

namespace Sentinel.Persistence.Core;

public abstract class EfDocumentStore<TContext>(
    TContext db,
    ILogger logger)
    : IDocumentStore
    where TContext : SentinelDbContext
{
    protected TContext Db { get; } = db;

    protected ILogger Logger { get; } = logger;

    public async Task<PagedResult<DocumentDto>> ListAsync(
        string ownerSub,
        DocumentQuery query,
        CancellationToken cancellationToken)
    {
        int page = Math.Max(1, query.Page);
        int pageSize = Math.Clamp(query.PageSize, 1, 200);

        IQueryable<Document> documentQuery = Db.Documents
            .Where(document => document.OwnerSub == ownerSub);

        if (!string.IsNullOrWhiteSpace(query.SearchTerm))
        {
            documentQuery = ApplySearch(documentQuery, query.SearchTerm.Trim());
        }

        documentQuery = ApplySort(documentQuery, query.SortBy);

        int totalCount = await documentQuery.CountAsync(cancellationToken);
        List<Document> items = await documentQuery
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken);

        return new PagedResult<DocumentDto>(
            items.Select(MapToDto).ToArray(),
            totalCount,
            page,
            pageSize);
    }

    public async Task<DocumentDto?> GetByIdAsync(Guid id, string ownerSub, CancellationToken cancellationToken)
    {
        Document? document = await Db.Documents
            .FirstOrDefaultAsync(
                entity => entity.Id == id && entity.OwnerSub == ownerSub,
                cancellationToken);

        return document is null ? null : MapToDto(document);
    }

    public async Task<DocumentDto> CreateAsync(
        string ownerSub,
        CreateDocumentRequest request,
        CancellationToken cancellationToken)
    {
        Document document = Document.Create(ownerSub, request.Title, request.Content);

        Db.Documents.Add(document);
        await Db.SaveChangesAsync(cancellationToken);

        Logger.LogInformation(
            "Document {DocumentId} created for sub {OwnerSub}",
            document.Id,
            ownerSub);

        return MapToDto(document);
    }

    public async Task<DocumentDto?> UpdateAsync(
        Guid id,
        string ownerSub,
        UpdateDocumentRequest request,
        string rowVersion,
        CancellationToken cancellationToken)
    {
        Document? document = await Db.Documents
            .FirstOrDefaultAsync(
                entity => entity.Id == id && entity.OwnerSub == ownerSub,
                cancellationToken);

        if (document is null)
        {
            return null;
        }

        SetOriginalRowVersion(document, rowVersion);
        document.Update(request.Title, request.Content);

        try
        {
            await Db.SaveChangesAsync(cancellationToken);
            return MapToDto(document);
        }
        catch (DbUpdateConcurrencyException exception)
        {
            Logger.LogWarning(exception, "Concurrency conflict on document {DocumentId}", id);
            throw new DocumentConcurrencyException(id);
        }
    }

    public async Task<bool> DeleteAsync(Guid id, string ownerSub, CancellationToken cancellationToken)
    {
        Document? document = await Db.Documents
            .FirstOrDefaultAsync(
                entity => entity.Id == id && entity.OwnerSub == ownerSub,
                cancellationToken);

        if (document is null)
        {
            return false;
        }

        document.SoftDelete();

        try
        {
            await Db.SaveChangesAsync(cancellationToken);
            Logger.LogInformation(
                "Document {DocumentId} soft-deleted for sub {OwnerSub}",
                id,
                ownerSub);
            return true;
        }
        catch (DbUpdateConcurrencyException exception)
        {
            Logger.LogWarning(exception, "Concurrency conflict during delete for document {DocumentId}", id);
            throw new DocumentConcurrencyException(id);
        }
    }

    protected abstract IQueryable<Document> ApplySearch(IQueryable<Document> query, string searchTerm);

    protected abstract string GetRowVersion(Document document);

    protected abstract void SetOriginalRowVersion(Document document, string rowVersion);

    protected virtual DocumentDto MapToDto(Document document) =>
        new(
            document.Id,
            document.OwnerSub,
            document.Title,
            document.Content,
            document.CreatedAtUtc,
            document.UpdatedAtUtc,
            GetRowVersion(document));

    private static IQueryable<Document> ApplySort(IQueryable<Document> query, DocumentSortBy sortBy) =>
        sortBy switch
        {
            DocumentSortBy.UpdatedAtAsc => query.OrderBy(document => document.UpdatedAtUtc),
            DocumentSortBy.TitleAsc => query.OrderBy(document => document.Title),
            DocumentSortBy.TitleDesc => query.OrderByDescending(document => document.Title),
            DocumentSortBy.CreatedAtDesc => query.OrderByDescending(document => document.CreatedAtUtc),
            _ => query.OrderByDescending(document => document.UpdatedAtUtc)
        };
}
