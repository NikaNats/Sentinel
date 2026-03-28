using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Domain.Notifications;

namespace Sentinel.Infrastructure.Auth;

internal sealed class LoggingEmailService(
    ILogger<LoggingEmailService> logger,
    IOptions<RegistrationOptions> registrationOptions,
    INotificationService notificationService) : IEmailService
{
    public async Task SendVerificationEmailAsync(string email, string verificationToken, CancellationToken ct)
    {
        var baseUri = registrationOptions.Value.VerificationBaseUrl;
        var verificationUrl = baseUri is null
            ? $"/v1/users/verify-email?token={verificationToken}"
            : new Uri(baseUri, $"/v1/users/verify-email?token={Uri.EscapeDataString(verificationToken)}").ToString();

        await notificationService.QueueNotificationAsync(
            new NotificationMessage(
                new NotificationRecipient(email),
                "Please verify your email",
                "EmailVerification",
                new VerificationTemplateData(verificationUrl)),
            ct);

        logger.LogInformation("Verification email queued for recipient {Recipient} using template {TemplateName}.",
            email, "EmailVerification");
    }

    public async Task SendResetPasswordEmailAsync(string email, string resetToken, CancellationToken ct)
    {
        var baseUri = registrationOptions.Value.VerificationBaseUrl;
        var resetUrl = baseUri is null
            ? $"/reset-password?token={Uri.EscapeDataString(resetToken)}"
            : new Uri(baseUri, $"/reset-password?token={Uri.EscapeDataString(resetToken)}").ToString();

        await notificationService.QueueNotificationAsync(
            new NotificationMessage(
                new NotificationRecipient(email),
                "Password reset request",
                "PasswordReset",
                new ResetPasswordTemplateData(resetUrl)),
            ct);

        logger.LogInformation("Reset password email queued for recipient {Recipient} using template {TemplateName}.",
            email, "PasswordReset");
    }

    public Task SendWelcomeOrAlreadyRegisteredEmailAsync(string email, CancellationToken ct)
    {
        _ = ct;
        logger.LogInformation("Registration status email requested for recipient {Recipient}.", email);
        return Task.CompletedTask;
    }

    private sealed record VerificationTemplateData(string VerificationUrl);

    private sealed record ResetPasswordTemplateData(string ResetUrl);
}
