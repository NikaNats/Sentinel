using Sentinel.Domain.Notifications;

namespace Sentinel.Infrastructure.Notifications;

internal interface INotificationDispatcher
{
    Task DispatchAsync(NotificationMessage message, CancellationToken ct);
}
