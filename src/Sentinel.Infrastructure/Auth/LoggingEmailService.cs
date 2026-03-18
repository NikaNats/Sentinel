using Microsoft.Extensions.Options;
using Sentinel.Application.Auth.Interfaces;

namespace Sentinel.Infrastructure.Auth;

public sealed class LoggingEmailService(
    ILogger<LoggingEmailService> logger,
    IOptions<RegistrationOptions> registrationOptions) : IEmailService
{
    public Task SendVerificationEmailAsync(string email, string verificationToken, CancellationToken ct)
    {
        _ = ct;

        var baseUri = registrationOptions.Value.VerificationBaseUrl;
        var verificationUrl = baseUri is null
            ? $"/v1/users/verify-email?token={verificationToken}"
            : new Uri(baseUri, $"/v1/users/verify-email?token={Uri.EscapeDataString(verificationToken)}").ToString();

        logger.LogInformation("Verification email requested for {Email}. Verification URL: {VerificationUrl}", email, verificationUrl);
        return Task.CompletedTask;
    }

    public Task SendResetPasswordEmailAsync(string email, string resetToken, CancellationToken ct)
    {
        _ = ct;

        var baseUri = registrationOptions.Value.VerificationBaseUrl;
        var resetUrl = baseUri is null
            ? $"/reset-password?token={Uri.EscapeDataString(resetToken)}"
            : new Uri(baseUri, $"/reset-password?token={Uri.EscapeDataString(resetToken)}").ToString();

        logger.LogInformation("Reset password email requested for {Email}. Reset URL: {ResetUrl}", email, resetUrl);
        return Task.CompletedTask;
    }
}
