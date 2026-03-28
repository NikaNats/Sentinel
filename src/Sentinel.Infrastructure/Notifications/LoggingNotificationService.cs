using Sentinel.Application.Common.Abstractions;
using Sentinel.Domain.Notifications;

namespace Sentinel.Infrastructure.Notifications;

internal sealed class LoggingNotificationService(ILogger<LoggingNotificationService> logger) : INotificationService
{
    public Task QueueNotificationAsync(NotificationMessage message, CancellationToken ct)
    {
        _ = ct;
        logger.LogInformation("NOTIFICATION QUEUED: {Type} to {Recipient} - {Subject}",
            message.Type, message.To.Identifier, message.Subject);
        return Task.CompletedTask;
    }
}
