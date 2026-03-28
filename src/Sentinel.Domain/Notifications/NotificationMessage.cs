namespace Sentinel.Domain.Notifications;

/// <summary>
///     Generic notification message enabling type-safe template data serialization.
///     Replaces object TemplateData with TData generic parameter for Native AOT compatibility.
///     Template data is strongly typed and source-generator compatible.
/// </summary>
/// <typeparam name="TData">Template data type (e.g., PasswordResetTemplateData, WelcomeTemplateData).</typeparam>
public sealed record NotificationMessage<TData>(
    NotificationRecipient To,
    string Subject,
    string TemplateName,
    TData TemplateData,
    NotificationType Type = NotificationType.Email)
    where TData : notnull;

/// <summary>
///     Non-generic base for backward compatibility and reflection-based scenarios.
///     Use NotificationMessage&lt;TData&gt; for new code in Native AOT paths.
/// </summary>
public sealed record NotificationMessage(
    NotificationRecipient To,
    string Subject,
    string TemplateName,
    object TemplateData,
    NotificationType Type = NotificationType.Email)
{
    /// <summary>
    ///     Convert to generic form for type-safe use.
    ///     Throws InvalidOperationException if TData doesn't match actual TemplateData type.
    /// </summary>
    public NotificationMessage<TData> AsGeneric<TData>() where TData : notnull
    {
        if (TemplateData is not TData typedData)
        {
            throw new InvalidOperationException(
                $"Template data is {TemplateData?.GetType().Name ?? "null"}, " +
                $"expected {typeof(TData).Name}");
        }

        return new NotificationMessage<TData>(To, Subject, TemplateName, typedData, Type);
    }
}
