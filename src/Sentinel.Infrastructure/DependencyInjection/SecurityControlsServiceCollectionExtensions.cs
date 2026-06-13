using Microsoft.Extensions.DependencyInjection;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Options;
using Sentinel.Infrastructure.Auth;

namespace Sentinel.Infrastructure.DependencyInjection;

public static class SecurityControlsServiceCollectionExtensions
{
    public static IServiceCollection AddSecurityControls(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // 1. Register password policy options and validator
        services.Configure<PasswordPolicyOptions>(
            configuration.GetSection(PasswordPolicyOptions.SectionName));

        services.AddSingleton<IPasswordStrengthValidator, EnterprisePasswordStrengthValidator>();

        // 2. Validate CAPTCHA options at startup (Fail-Fast)
        services.AddOptions<CaptchaOptions>()
            .Bind(configuration.GetSection(CaptchaOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        // 3. Register CAPTCHA service with resilient HttpClient
        services.AddHttpClient<ICaptchaService, CloudflareTurnstileCaptchaService>((sp, client) =>
        {
            var options = sp.GetRequiredService<IOptions<CaptchaOptions>>().Value;

            client.BaseAddress = options.VerificationUrl;
            client.Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds);

            client.DefaultRequestHeaders.Add("User-Agent", "Sentinel-Security-Gateway/2.0");
        });

        return services;
    }
}
