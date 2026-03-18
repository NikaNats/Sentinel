using Sentinel.Domain.Notifications;

namespace Sentinel.Application.Common.Abstractions;

public interface INotificationService
{
    Task QueueNotificationAsync(NotificationMessage message, CancellationToken ct);
}
