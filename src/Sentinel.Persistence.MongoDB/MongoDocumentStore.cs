using System.Text.RegularExpressions;
using MongoDB.Bson;
using MongoDB.Driver;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Application.Models;
using Sentinel.Domain.Documents;

namespace Sentinel.Persistence.MongoDB;

public sealed class MongoDocumentStore(
    IMongoCollection<MongoDocumentEntity> collection,
    ILogger<MongoDocumentStore> logger)
    : IDocumentStore
{
    public async Task<PagedResult<DocumentDto>> ListAsync(
        string ownerSub,
        DocumentQuery query,
        CancellationToken cancellationToken)
    {
        int page = Math.Max(1, query.Page);
        int pageSize = Math.Clamp(query.PageSize, 1, 200);

        FilterDefinition<MongoDocumentEntity> filter = Builders<MongoDocumentEntity>.Filter.And(
            Builders<MongoDocumentEntity>.Filter.Eq(document => document.OwnerSub, ownerSub),
            Builders<MongoDocumentEntity>.Filter.Eq(document => document.IsDeleted, false));

        if (!string.IsNullOrWhiteSpace(query.SearchTerm))
        {
            string escaped = Regex.Escape(query.SearchTerm.Trim());
            FilterDefinition<MongoDocumentEntity> searchFilter = Builders<MongoDocumentEntity>.Filter.Or(
                Builders<MongoDocumentEntity>.Filter.Regex(document => document.Title, new BsonRegularExpression(escaped, "i")),
                Builders<MongoDocumentEntity>.Filter.Regex(document => document.Content, new BsonRegularExpression(escaped, "i")));
            filter &= searchFilter;
        }

        SortDefinition<MongoDocumentEntity> sort = query.SortBy switch
        {
            DocumentSortBy.UpdatedAtAsc => Builders<MongoDocumentEntity>.Sort.Ascending(document => document.UpdatedAtUtc),
            DocumentSortBy.TitleAsc => Builders<MongoDocumentEntity>.Sort.Ascending(document => document.Title),
            DocumentSortBy.TitleDesc => Builders<MongoDocumentEntity>.Sort.Descending(document => document.Title),
            DocumentSortBy.CreatedAtDesc => Builders<MongoDocumentEntity>.Sort.Descending(document => document.CreatedAtUtc),
            _ => Builders<MongoDocumentEntity>.Sort.Descending(document => document.UpdatedAtUtc)
        };

        long totalCount = await collection.CountDocumentsAsync(filter, cancellationToken: cancellationToken);
        List<MongoDocumentEntity> items = await collection.Find(filter)
            .Sort(sort)
            .Skip((page - 1) * pageSize)
            .Limit(pageSize)
            .ToListAsync(cancellationToken);

        return new PagedResult<DocumentDto>(
            items.Select(MapToDto).ToArray(),
            (int)totalCount,
            page,
            pageSize);
    }

    public async Task<DocumentDto?> GetByIdAsync(Guid id, string ownerSub, CancellationToken cancellationToken)
    {
        MongoDocumentEntity? entity = await collection.Find(document =>
                document.Id == id
                && document.OwnerSub == ownerSub
                && !document.IsDeleted)
            .FirstOrDefaultAsync(cancellationToken);

        return entity is null ? null : MapToDto(entity);
    }

    public async Task<DocumentDto> CreateAsync(
        string ownerSub,
        CreateDocumentRequest request,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        MongoDocumentEntity entity = new()
        {
            Id = Guid.NewGuid(),
            OwnerSub = ownerSub,
            Title = request.Title.Trim(),
            Content = request.Content,
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        };

        await collection.InsertOneAsync(entity, cancellationToken: cancellationToken);

        logger.LogInformation("Document {DocumentId} created for sub {OwnerSub}", entity.Id, ownerSub);
        return MapToDto(entity);
    }

    public async Task<DocumentDto?> UpdateAsync(
        Guid id,
        string ownerSub,
        UpdateDocumentRequest request,
        string rowVersion,
        CancellationToken cancellationToken)
    {
        if (!long.TryParse(rowVersion, out long expectedVersion))
        {
            throw new ArgumentException("Invalid rowVersion for MongoDB.", nameof(rowVersion));
        }

        FilterDefinition<MongoDocumentEntity> filter = Builders<MongoDocumentEntity>.Filter.And(
            Builders<MongoDocumentEntity>.Filter.Eq(document => document.Id, id),
            Builders<MongoDocumentEntity>.Filter.Eq(document => document.OwnerSub, ownerSub),
            Builders<MongoDocumentEntity>.Filter.Eq(document => document.IsDeleted, false),
            Builders<MongoDocumentEntity>.Filter.Eq(document => document.Version, expectedVersion));

        UpdateDefinition<MongoDocumentEntity> update = Builders<MongoDocumentEntity>.Update
            .Set(document => document.Title, request.Title.Trim())
            .Set(document => document.Content, request.Content)
            .Set(document => document.UpdatedAtUtc, DateTimeOffset.UtcNow)
            .Inc(document => document.Version, 1);

        MongoDocumentEntity? updated = await collection.FindOneAndUpdateAsync(
            filter,
            update,
            new FindOneAndUpdateOptions<MongoDocumentEntity>
            {
                ReturnDocument = ReturnDocument.After
            },
            cancellationToken);

        if (updated is not null)
        {
            return MapToDto(updated);
        }

        bool exists = await collection.Find(document =>
                document.Id == id
                && document.OwnerSub == ownerSub
                && !document.IsDeleted)
            .AnyAsync(cancellationToken);

        if (exists)
        {
            throw new DocumentConcurrencyException(id);
        }

        return null;
    }

    public async Task<bool> DeleteAsync(Guid id, string ownerSub, CancellationToken cancellationToken)
    {
        UpdateResult result = await collection.UpdateOneAsync(
            document => document.Id == id && document.OwnerSub == ownerSub && !document.IsDeleted,
            Builders<MongoDocumentEntity>.Update
                .Set(document => document.IsDeleted, true)
                .Set(document => document.DeletedAtUtc, DateTimeOffset.UtcNow)
                .Set(document => document.UpdatedAtUtc, DateTimeOffset.UtcNow)
                .Inc(document => document.Version, 1),
            cancellationToken: cancellationToken);

        return result.ModifiedCount > 0;
    }

    private static DocumentDto MapToDto(MongoDocumentEntity entity) =>
        new(
            entity.Id,
            entity.OwnerSub,
            entity.Title,
            entity.Content,
            entity.CreatedAtUtc,
            entity.UpdatedAtUtc,
            entity.Version.ToString());
}
