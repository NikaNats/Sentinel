using Microsoft.Extensions.Logging;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Security.Abstractions.Identity;
using Sentinel.Security.Abstractions.Results;

namespace Sentinel.Application.Auth;

public sealed class ResendVerificationHandler(
    IIdentityProvider identityProvider,
    IEmailVerificationTokenStore verificationTokenStore,
    IEmailService emailService,
    ILogger<ResendVerificationHandler> logger)
{
    /// <summary>
    /// Handles email verification resend with anti-enumeration behavior.
    /// Validates email → looks up user → generates token → sends verification email.
    /// Returns success regardless to prevent user enumeration via error messages.
    /// </summary>
    public async Task<SecurityResult> HandleAsync(ResendVerificationRequest request, CancellationToken ct)
    {
        // Validate input (but don't reveal validation failures)
        if (string.IsNullOrWhiteSpace(request.Email))
        {
            // Anti-enumeration: return success even on invalid input
            return SecurityResultFactory.Create();
        }

        try
        {
            var normalizedEmail = request.Email.Trim();

            // Check if user exists (but don't reveal in response)
            var user = await identityProvider.GetUserByEmailAsync(normalizedEmail, ct);
            if (user is null)
            {
                // Anti-enumeration: return success even if user doesn't exist
                return SecurityResultFactory.Create();
            }

            // Generate verification token
            var verificationToken = Guid.NewGuid().ToString("N");
            var tokenStored = await verificationTokenStore.StoreAsync(
                verificationToken,
                user.Id,
                TimeSpan.FromHours(24),
                ct);

            // Log storage failure but return success
            if (!tokenStored)
            {
                logger.LogWarning("Could not store verification token for user {UserId}.", user.Id);
                return SecurityResultFactory.Create();
            }

            // Send verification email
            await emailService.SendVerificationEmailAsync(normalizedEmail, verificationToken, ct);
            return SecurityResultFactory.Create();
        }
#pragma warning disable CA1031 // Intentional catch-all: resend verification must not leak account existence via error behavior.
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Resend verification failed for {Email}.", request.Email);
            // Anti-enumeration: return success even on exception
            return SecurityResultFactory.Create();
        }
#pragma warning restore CA1031
    }
}
