namespace Sentinel.Security.Captcha;

public static class CaptchaServiceCollectionExtensions
{
    public static IServiceCollection AddTurnstileService(this IServiceCollection services, Action<CaptchaOptions>? configure = null)
    {
        if (configure != null)
            services.Configure(configure);

        services.AddHttpClient<ICaptchaService, TurnstileService>();
        return services;
    }
}
