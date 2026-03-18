using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Application.Common.Abstractions;

namespace Sentinel.Infrastructure.Notifications;

public interface ISentinelSecurityBuilder
{
    IServiceCollection Services { get; }
}

internal sealed class SentinelSecurityBuilder(IServiceCollection services) : ISentinelSecurityBuilder
{
    public IServiceCollection Services { get; } = services;
}

public static class SentinelNotificationExtensions
{
    public static ISentinelSecurityBuilder AddNotifications(this IServiceCollection services, IConfiguration configuration)
    {
        _ = services.Configure<NotificationOptions>(configuration.GetSection("Notifications"));
        _ = services.Configure<SendGridOptions>(configuration.GetSection("Notifications:SendGrid"));
        _ = services.Configure<TwilioOptions>(configuration.GetSection("Notifications:Twilio"));

        _ = services.AddSingleton<ITemplateRenderer, FluidTemplateRenderer>();
        _ = services.AddSingleton<INotificationQueue, NotificationQueue>();
        _ = services.AddSingleton<INotificationDispatcher, NotificationDispatcher>();
        _ = services.AddSingleton<INotificationService, NotificationService>();
        _ = services.AddHostedService<NotificationBackgroundService>();

        return new SentinelSecurityBuilder(services);
    }

    public static ISentinelSecurityBuilder AddSendGrid(this ISentinelSecurityBuilder builder, Action<SendGridOptions>? configure = null)
    {
        if (configure is not null)
        {
            _ = builder.Services.Configure(configure);
        }

        _ = builder.Services.AddHttpClient<INotificationProvider, SendGridProvider>();
        return builder;
    }

    public static ISentinelSecurityBuilder AddTwilio(this ISentinelSecurityBuilder builder, Action<TwilioOptions>? configure = null)
    {
        if (configure is not null)
        {
            _ = builder.Services.Configure(configure);
        }

        _ = builder.Services.AddHttpClient<INotificationProvider, TwilioSmsProvider>();
        return builder;
    }
}
