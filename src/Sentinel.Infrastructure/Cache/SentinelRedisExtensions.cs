using Microsoft.Extensions.DependencyInjection;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Notifications;
using StackExchange.Redis;

namespace Sentinel.Infrastructure.Cache;

public static class SentinelRedisExtensions
{
    public static IServiceCollection AddSentinelSecureRedis(this IServiceCollection services,
        IConfiguration configuration)
    {
        _ = services.Configure<RedisOptions>(configuration.GetSection("Sentinel:Redis"));
        _ = services.AddMemoryCache();

        var configuredOptions = configuration.GetSection("Sentinel:Redis").Get<RedisOptions>() ?? new RedisOptions();
        var fallbackConnectionString = configuration.GetConnectionString("Redis");
        var redisConfiguration = RedisConnectionFactory.BuildOptions(configuredOptions, fallbackConnectionString);

        _ = services.AddStackExchangeRedisCache(options => { options.ConfigurationOptions = redisConfiguration; });

        _ = services.AddSingleton<IConnectionMultiplexer>(_ => ConnectionMultiplexer.Connect(redisConfiguration));

        _ = services.AddSingleton<IJtiReplayCache, HybridJtiReplayCache>();
        _ = services.AddSingleton<IDpopNonceStore, HybridNonceStore>();

        return services;
    }

    public static ISentinelSecurityBuilder AddSecureRedis(this ISentinelSecurityBuilder builder,
        IConfiguration configuration)
    {
        _ = builder.Services.AddSentinelSecureRedis(configuration);
        return builder;
    }
}
