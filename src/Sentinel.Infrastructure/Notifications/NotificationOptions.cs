namespace Sentinel.Infrastructure.Notifications;

public sealed class NotificationOptions
{
    public int QueueCapacity { get; set; } = 512;
    public int MaxRetryAttempts { get; set; } = 3;
    public int RetryDelaySeconds { get; set; } = 2;
    public string TemplateRootPath { get; set; } = "Templates";
}
