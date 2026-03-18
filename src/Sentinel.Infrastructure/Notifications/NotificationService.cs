using Sentinel.Application.Common.Abstractions;
using Sentinel.Domain.Notifications;

namespace Sentinel.Infrastructure.Notifications;

internal sealed class NotificationService(
    INotificationQueue queue,
    ILogger<NotificationService> logger) : INotificationService
{
    public async Task QueueNotificationAsync(NotificationMessage message, CancellationToken ct)
    {
        await queue.EnqueueAsync(message, ct);
        logger.LogInformation(
            "Notification queued for recipient {Recipient} with template {TemplateName}.",
            message.To.Identifier,
            message.TemplateName);
    }
}
