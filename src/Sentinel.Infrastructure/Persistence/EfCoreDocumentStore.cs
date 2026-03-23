using Microsoft.EntityFrameworkCore;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Application.Models;

namespace Sentinel.Infrastructure.Persistence;

internal sealed class EfCoreDocumentStore(SentinelDbContext dbContext, TimeProvider? timeProvider = null) : IDocumentStore
{
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    public async Task<IReadOnlyCollection<DocumentDto>> ListAsync(string ownerSub, CancellationToken cancellationToken)
    {
        return await dbContext.Documents
            .AsNoTracking()
            .Where(d => d.OwnerSub == ownerSub)
            .OrderByDescending(d => d.UpdatedAtUtc)
            .Select(d => new DocumentDto(d.Id, d.OwnerSub, d.Title, d.Content, d.CreatedAtUtc, d.UpdatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    public async Task<DocumentDto?> GetByIdAsync(Guid id, string ownerSub, CancellationToken cancellationToken)
    {
        var doc = await dbContext.Documents
            .AsNoTracking()
            .FirstOrDefaultAsync(d => d.Id == id && d.OwnerSub == ownerSub, cancellationToken);

        return doc is null
            ? null
            : new DocumentDto(doc.Id, doc.OwnerSub, doc.Title, doc.Content, doc.CreatedAtUtc, doc.UpdatedAtUtc);
    }

    public async Task<DocumentDto> CreateAsync(string ownerSub, CreateDocumentRequest request,
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

        return new DocumentDto(entity.Id, entity.OwnerSub, entity.Title, entity.Content, entity.CreatedAtUtc,
            entity.UpdatedAtUtc);
    }

    public async Task<DocumentDto?> UpdateAsync(Guid id, string ownerSub, UpdateDocumentRequest request,
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

        return new DocumentDto(entity.Id, entity.OwnerSub, entity.Title, entity.Content, entity.CreatedAtUtc,
            entity.UpdatedAtUtc);
    }

    public async Task<bool> DeleteAsync(Guid id, string ownerSub, CancellationToken cancellationToken)
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
