using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sentinel.Domain.Notifications;

namespace Sentinel.Infrastructure.Notifications;

internal sealed class NotificationBackgroundService(
    INotificationQueue queue,
    INotificationDispatcher dispatcher,
    IOptions<NotificationOptions> options,
    ILogger<NotificationBackgroundService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var message in queue.DequeueAllAsync(stoppingToken))
        {
            await ProcessAsync(message, stoppingToken);
        }
    }

    private async Task ProcessAsync(NotificationMessage message, CancellationToken ct)
    {
        var maxAttempts = Math.Max(1, options.Value.MaxRetryAttempts);
        var retryDelay = TimeSpan.FromSeconds(Math.Max(1, options.Value.RetryDelaySeconds));

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                await dispatcher.DispatchAsync(message, ct);
                return;
            }
            catch (Exception ex) when (attempt < maxAttempts)
            {
                logger.LogWarning(
                    ex,
                    "Notification send attempt {Attempt} failed for recipient {Recipient} (template {TemplateName}). Retrying.",
                    attempt,
                    message.To.Identifier,
                    message.TemplateName);

                await Task.Delay(retryDelay, ct);
            }
            catch (Exception ex)
            {
                logger.LogError(
                    ex,
                    "Notification send permanently failed for recipient {Recipient} after {Attempts} attempts (template {TemplateName}).",
                    message.To.Identifier,
                    maxAttempts,
                    message.TemplateName);
            }
        }
    }
}
