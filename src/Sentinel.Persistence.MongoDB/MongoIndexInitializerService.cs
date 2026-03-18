using MongoDB.Driver;

namespace Sentinel.Persistence.MongoDB;

public sealed class MongoIndexInitializerService(IMongoCollection<MongoDocumentEntity> collection) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken) =>
        MongoIndexInitializer.EnsureIndexesAsync(collection, cancellationToken);

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
