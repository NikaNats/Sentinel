using Microsoft.Extensions.DependencyInjection;
using Sentinel.Keycloak.Extensions;

namespace Sentinel.Infrastructure.DependencyInjection;

public static class InfrastructureServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructureLayer(this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        _ = services
            .AddSentinelCore(configuration)
            .AddDPoP(configuration)
            .AddKeycloak(configuration)
            .AddNotificationsModule(configuration)
            .AddTelemetry();

        _ = services.AddSecurityControls(configuration);

        return services;
    }
}
