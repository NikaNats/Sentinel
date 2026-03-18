using Sentinel.Application.Common.Abstractions;
using Sentinel.Domain.Notifications;

namespace Sentinel.Infrastructure.Notifications;

internal sealed class NotificationDispatcher(
    IEnumerable<INotificationProvider> providers,
    ITemplateRenderer templateRenderer,
    ILogger<NotificationDispatcher> logger) : INotificationDispatcher
{
    public async Task DispatchAsync(NotificationMessage message, CancellationToken ct)
    {
        var provider = providers.FirstOrDefault(p => p.CanHandle(message.Type));
        if (provider is null)
        {
            throw new InvalidOperationException("No notification provider configured for type " + message.Type + ".");
        }

        var body = await templateRenderer.RenderAsync(message.TemplateName, message.TemplateData, ct);
        await provider.SendAsync(message, body, ct);

        logger.LogInformation(
            "Notification sent via {Provider} for recipient {Recipient} using template {TemplateName}.",
            provider.ProviderName,
            message.To.Identifier,
            message.TemplateName);
    }
}
