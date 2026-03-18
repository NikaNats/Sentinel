using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Persistence.Core;

namespace Sentinel.Persistence.Postgres;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSentinelPostgres(
        this IServiceCollection services,
        string connectionString,
        Action<PostgresPersistenceOptions>? configure = null)
    {
        PostgresPersistenceOptions options = new();
        configure?.Invoke(options);

        services.AddHttpContextAccessor();
        services.AddDbContext<PostgresSentinelDbContext>(db =>
        {
            db.UseNpgsql(connectionString, npgsql =>
            {
                npgsql.EnableRetryOnFailure(options.MaxRetryCount);
                npgsql.CommandTimeout(options.CommandTimeoutSeconds);
            });

            if (options.EnableSensitiveDataLogging)
            {
                db.EnableSensitiveDataLogging();
            }
        });

        services.AddScoped<SentinelDbContext>(serviceProvider =>
            serviceProvider.GetRequiredService<PostgresSentinelDbContext>());
        services.AddScoped<IDocumentStore, PostgresDocumentStore>();

        return services;
    }
}
