namespace Sentinel.Domain.Notifications;

public sealed record NotificationMessage(
    NotificationRecipient To,
    string Subject,
    string TemplateName,
    object TemplateData,
    NotificationType Type = NotificationType.Email);
