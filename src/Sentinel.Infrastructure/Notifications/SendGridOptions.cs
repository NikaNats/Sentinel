namespace Sentinel.Infrastructure.Notifications;

public sealed class SendGridOptions
{
    public string ApiKey { get; set; } = string.Empty;
    public string FromEmail { get; set; } = string.Empty;
    public bool Enabled { get; set; }
}
