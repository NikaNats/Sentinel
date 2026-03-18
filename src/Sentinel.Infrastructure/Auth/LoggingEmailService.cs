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
}
