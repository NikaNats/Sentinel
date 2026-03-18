using Microsoft.AspNetCore.Builder;
using Sentinel.Persistence.Postgres;
using Sentinel.Persistence.SqlServer;

namespace Sentinel.Infrastructure.DependencyInjection;

public static class PersistenceApplicationBuilderExtensions
{
    public static WebApplication UseSentinelPersistence(this WebApplication app)
    {
        string provider = app.Configuration["Persistence:Provider"] ?? "InMemory";

        switch (provider.Trim().ToLowerInvariant())
        {
            case "postgres":
            case "postgresql":
                app.UseMiddleware<PostgresRlsMiddleware>();
                break;
            case "sqlserver":
                app.UseMiddleware<SqlServerRlsMiddleware>();
                break;
        }

        return app;
    }
}
