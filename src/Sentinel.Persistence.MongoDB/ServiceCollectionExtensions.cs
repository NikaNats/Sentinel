using Microsoft.Extensions.DependencyInjection;
using MongoDB.Driver;
using Sentinel.Application.Common.Abstractions;

namespace Sentinel.Persistence.MongoDB;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSentinelMongoDb(
        this IServiceCollection services,
        string connectionString,
        string databaseName = "sentinel",
        string collectionName = "documents")
    {
        services.AddSingleton<IMongoClient>(_ => new MongoClient(connectionString));
        services.AddSingleton(serviceProvider =>
        {
            IMongoClient client = serviceProvider.GetRequiredService<IMongoClient>();
            return client.GetDatabase(databaseName).GetCollection<MongoDocumentEntity>(collectionName);
        });

        services.AddHostedService<MongoIndexInitializerService>();
        services.AddScoped<IDocumentStore, MongoDocumentStore>();

        return services;
    }
}
