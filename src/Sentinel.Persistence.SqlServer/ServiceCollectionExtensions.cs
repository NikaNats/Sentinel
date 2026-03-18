using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Persistence.Core;

namespace Sentinel.Persistence.SqlServer;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSentinelSqlServer(
        this IServiceCollection services,
        string connectionString,
        Action<SqlServerPersistenceOptions>? configure = null)
    {
        SqlServerPersistenceOptions options = new();
        configure?.Invoke(options);

        services.AddHttpContextAccessor();
        services.AddDbContext<SqlServerSentinelDbContext>(db =>
        {
            db.UseSqlServer(connectionString, sql =>
            {
                sql.EnableRetryOnFailure(options.MaxRetryCount);
                sql.CommandTimeout(options.CommandTimeoutSeconds);
            });

            if (options.EnableSensitiveDataLogging)
            {
                db.EnableSensitiveDataLogging();
            }
        });

        services.AddScoped<SentinelDbContext>(serviceProvider =>
            serviceProvider.GetRequiredService<SqlServerSentinelDbContext>());
        services.AddScoped<IDocumentStore, SqlServerDocumentStore>();

        return services;
    }
}
