using Sentinel.Domain.Notifications;

namespace Sentinel.Application.Common.Abstractions;

public interface INotificationProvider
{
    string ProviderName { get; }
    bool CanHandle(NotificationType notificationType);
    Task SendAsync(NotificationMessage message, string body, CancellationToken ct);
}
