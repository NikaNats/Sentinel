namespace Sentinel.Domain.Notifications;

public sealed record NotificationRecipient(string Identifier, string? Name = null);
