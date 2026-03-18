using Sentinel.Domain.Notifications;

namespace Sentinel.Infrastructure.Notifications;

internal interface INotificationQueue
{
    ValueTask EnqueueAsync(NotificationMessage message, CancellationToken ct);
    IAsyncEnumerable<NotificationMessage> DequeueAllAsync(CancellationToken ct);
}
