using MongoDB.Driver;

namespace Sentinel.Persistence.MongoDB;

public static class MongoIndexInitializer
{
    public static Task EnsureIndexesAsync(
        IMongoCollection<MongoDocumentEntity> collection,
        CancellationToken cancellationToken = default)
    {
        CreateIndexModel<MongoDocumentEntity>[] indexes =
        [
            new(Builders<MongoDocumentEntity>.IndexKeys
                .Ascending(document => document.OwnerSub)
                .Ascending(document => document.IsDeleted)
                .Descending(document => document.UpdatedAtUtc)),
            new(Builders<MongoDocumentEntity>.IndexKeys
                .Ascending(document => document.OwnerSub)
                .Ascending(document => document.Version))
        ];

        return collection.Indexes.CreateManyAsync(indexes, cancellationToken: cancellationToken);
    }
}
