using Microsoft.EntityFrameworkCore;
using Sentinel.SampleHost.Models;

namespace Sentinel.SampleHost.Stores;

internal sealed class EfCoreDocumentStore(SampleHostDbContext dbContext, TimeProvider? timeProvider = null) : IDocumentStore
{
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    async Task<IReadOnlyCollection<DocumentDto>> IDocumentStore.ListAsync(
        string ownerSub, CancellationToken cancellationToken)
    {
        var dtos = await dbContext.Documents
            .AsNoTracking()
            .Where(d => d.OwnerSub == ownerSub)
            .OrderByDescending(d => d.UpdatedAtUtc)
            .Select(d => new DocumentDto(
                d.Id, d.OwnerSub, d.Title, d.Content, d.CreatedAtUtc, d.UpdatedAtUtc))
            .ToListAsync(cancellationToken);

        return dtos;
    }

    async Task<DocumentDto?> IDocumentStore.GetByIdAsync(
        Guid id, string ownerSub, CancellationToken cancellationToken)
    {
        var doc = await dbContext.Documents
            .AsNoTracking()
            .FirstOrDefaultAsync(d => d.Id == id && d.OwnerSub == ownerSub, cancellationToken);

        return doc is null
            ? null
            : new DocumentDto(
                doc.Id, doc.OwnerSub, doc.Title, doc.Content, doc.CreatedAtUtc, doc.UpdatedAtUtc);
    }

    async Task<DocumentDto> IDocumentStore.CreateAsync(
        string ownerSub, CreateDocumentRequest request,
        CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var entity = new DocumentEntity
        {
            Id = Guid.NewGuid(),
            OwnerSub = ownerSub,
            Title = request.Title,
            Content = request.Content,
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        };

        dbContext.Documents.Add(entity);
        _ = await dbContext.SaveChangesAsync(cancellationToken);

        return new DocumentDto(
            entity.Id, entity.OwnerSub, entity.Title, entity.Content, entity.CreatedAtUtc, entity.UpdatedAtUtc);
    }

    async Task<DocumentDto?> IDocumentStore.UpdateAsync(
        Guid id, string ownerSub, UpdateDocumentRequest request,
        CancellationToken cancellationToken)
    {
        var entity = await dbContext.Documents
            .AsTracking()
            .FirstOrDefaultAsync(d => d.Id == id && d.OwnerSub == ownerSub, cancellationToken);
        if (entity is null)
        {
            return null;
        }

        entity.Title = request.Title;
        entity.Content = request.Content;
        entity.UpdatedAtUtc = _timeProvider.GetUtcNow();

        _ = await dbContext.SaveChangesAsync(cancellationToken);

        return new DocumentDto(
            entity.Id, entity.OwnerSub, entity.Title, entity.Content, entity.CreatedAtUtc, entity.UpdatedAtUtc);
    }

    async Task<bool> IDocumentStore.DeleteAsync(Guid id, string ownerSub, CancellationToken cancellationToken)
    {
        var entity = await dbContext.Documents
            .AsTracking()
            .FirstOrDefaultAsync(d => d.Id == id && d.OwnerSub == ownerSub, cancellationToken);
        if (entity is null)
        {
            return false;
        }

        _ = dbContext.Documents.Remove(entity);
        _ = await dbContext.SaveChangesAsync(cancellationToken);

        return true;
    }
}
