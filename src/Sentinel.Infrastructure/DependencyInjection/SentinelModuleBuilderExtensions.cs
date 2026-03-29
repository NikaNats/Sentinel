using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Common.Abstractions;
using Sentinel.DPoP.Extensions;
using Sentinel.Infrastructure.Auth;
using Sentinel.Infrastructure.Cryptography;
using Sentinel.Infrastructure.Notifications;
using Sentinel.Security.Abstractions.DependencyInjection;
using Sentinel.Security.Abstractions.Security;
using Sentinel.Security.Diagnostics;
using Sentinel.Security.Diagnostics.Extensions;

namespace Sentinel.Infrastructure.DependencyInjection;

// Temporary implementation until real builder exists
public sealed class SentinelSecurityBuilder(IServiceCollection services) : ISentinelSecurityBuilder
{
    public IServiceCollection Services { get; } = services;
}

public static class SentinelModuleBuilderExtensions
{
    public static ISentinelSecurityBuilder AddSentinelCore(this IServiceCollection services,
        IConfiguration configuration)
    {
        _ = services.AddOptions<CryptographyOptions>()
            .BindConfiguration(CryptographyOptions.SectionName)
            .Validate(opts =>
            {
                if (string.IsNullOrWhiteSpace(opts.ActiveKeyId))
                {
                    return false;
                }

                return opts.KeyRing.ContainsKey(opts.ActiveKeyId);
            }, "Cryptography:ActiveKeyId must reference an existing key in Cryptography:KeyRing.")
            .ValidateOnStart();

        _ = services.Configure<RegistrationOptions>(configuration.GetSection("Registration"));

        _ = services.AddSingleton<IEncryptionService, AesGcmEncryptionService>();

        _ = services.AddSingleton<ILogoutTokenValidator, LogoutTokenValidator>();
        _ = services.AddSingleton<ISecurityEventEmitter, SecurityEventEmitter>();
        _ = services.AddSingleton<TokenValidationService>();

        return new SentinelSecurityBuilder(services);
    }

    public static ISentinelSecurityBuilder AddDPoP(this ISentinelSecurityBuilder builder,
        IConfiguration? configuration = null)
    {
        if (configuration != null)
        {
            _ = builder.Services.AddSentinelDPoP(configuration);
        }

        return builder;
    }

    public static ISentinelSecurityBuilder AddNotificationsModule(this ISentinelSecurityBuilder builder,
        IConfiguration configuration)
    {
        _ = configuration;
        builder.Services.TryAddSingleton<INotificationService, LoggingNotificationService>();
        builder.Services.TryAddSingleton<IEmailService, LoggingEmailService>();
        return builder;
    }

    public static ISentinelSecurityBuilder AddTelemetry(this ISentinelSecurityBuilder builder)
    {
        return builder.AddSecurityTelemetry();
    }
}
