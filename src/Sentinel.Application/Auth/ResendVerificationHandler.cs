using Microsoft.Extensions.Logging;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;

namespace Sentinel.Application.Auth;

public sealed class ResendVerificationHandler(
    IKeycloakUserService keycloakUserService,
    IEmailVerificationTokenStore verificationTokenStore,
    IEmailService emailService,
    ILogger<ResendVerificationHandler> logger)
{
    public async Task HandleAsync(ResendVerificationRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Email))
        {
            return;
        }

        try
        {
            var normalizedEmail = request.Email.Trim();
            var user = await keycloakUserService.GetUserByEmailAsync(normalizedEmail, ct);
            if (user is null)
            {
                return;
            }

            var verificationToken = Guid.NewGuid().ToString("N");
            var stored = await verificationTokenStore.StoreAsync(verificationToken, user.Id, TimeSpan.FromHours(24), ct);
            if (!stored)
            {
                logger.LogWarning("Could not store verification token for user {UserId}.", user.Id);
                return;
            }

            await emailService.SendVerificationEmailAsync(normalizedEmail, verificationToken, ct);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Resend verification failed for {Email}.", request.Email);
        }
    }
}
