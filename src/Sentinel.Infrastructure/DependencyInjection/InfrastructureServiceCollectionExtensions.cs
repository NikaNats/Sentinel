using Microsoft.Extensions.DependencyInjection;

namespace Sentinel.Infrastructure.DependencyInjection;

public static class InfrastructureServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructureLayer(this IServiceCollection services,
        IConfiguration configuration)
    {
        _ = services
            .AddSentinelCore(configuration)
            .AddRedisReplayCache(configuration)
            .AddDPoP()
            .AddKeycloak()
            .AddNotificationsModule(configuration)
            .AddTelemetry()
            .AddJwtAndCertificateAuth(configuration);

        return services;
    }
}
