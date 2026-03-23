namespace Sentinel.Security.Tokens;

public static class TokenServiceCollectionExtensions
{
    public static IServiceCollection AddHmacTokenServices(this IServiceCollection services, Action<ResetTokenOptions>? configure = null)
    {
        if (configure != null)
            services.Configure(configure);

        services.AddSingleton<IResetTokenProvider, HmacResetTokenProvider>();
        return services;
    }
}
