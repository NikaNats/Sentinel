using Microsoft.Extensions.DependencyInjection;
using Sentinel.Keycloak.Extensions;
using Sentinel.Redis.Extensions;

namespace Sentinel.Infrastructure.DependencyInjection;

public static class InfrastructureServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructureLayer(this IServiceCollection services,
        IConfiguration configuration)
    {
        // Add Redis security caches (JTI replay, DPoP nonce, session blacklist)
        // MUST be called before AddSentinelCore() so IDpopProofValidator and TokenValidationService
        // can resolve their IJtiReplayCache dependency
        _ = services.AddRedisSecurityCaches(configuration.GetSection("Sentinel:Redis"));

        _ = services
            .AddSentinelCore(configuration)
            .AddDPoP(configuration)
            .AddKeycloak(configuration)
            .AddNotificationsModule(configuration)
            .AddTelemetry();

        return services;
    }
}
