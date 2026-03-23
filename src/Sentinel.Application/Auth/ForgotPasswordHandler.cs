using Microsoft.Extensions.Logging;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Domain.Auth;
using Sentinel.Security.Abstractions.Identity;
using Sentinel.Security.Abstractions.Results;

namespace Sentinel.Application.Auth;

public sealed class ForgotPasswordHandler(
    IIdentityProvider identityProvider,
    IResetTokenProvider resetTokenProvider,
    IEmailService emailService,
    ICaptchaService captchaService,
    ILogger<ForgotPasswordHandler> logger)
{
    /// <summary>
    /// Handles forgot password request with anti-enumeration behavior.
    /// Validates email and captcha → generates reset token → sends email.
    /// Returns success regardless to prevent user enumeration attacks.
    /// </summary>
    public async Task<SecurityResult> HandleAsync(ForgotPasswordRequest request, CancellationToken ct)
    {
        // Validate input (but don't reveal which validation failed)
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.CaptchaToken))
        {
            // Anti-enumeration: return success even on invalid input
            return SecurityResultFactory.Create();
        }

        // Verify captcha
        if (!await captchaService.VerifyAsync(request.CaptchaToken, ct))
        {
            // Anti-enumeration: return success even if captcha fails
            return SecurityResultFactory.Create();
        }

        try
        {
            // Check if user exists (but don't reveal this in response)
            var user = await identityProvider.GetUserByEmailAsync(request.Email.Trim(), ct);
            if (user is null)
            {
                // Anti-enumeration: return success even if user doesn't exist
                return SecurityResultFactory.Create();
            }

            // Generate and send reset token
            var token = resetTokenProvider.GenerateToken(request.Email.Trim());
            await emailService.SendResetPasswordEmailAsync(request.Email.Trim(), token, ct);

            return SecurityResultFactory.Create();
        }
#pragma warning disable CA1031 // Intentional catch-all: forgot-password must fail closed and maintain anti-enumeration behavior.
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Forgot password processing failed for {Email}.", request.Email);
            // Anti-enumeration: return success even on exception
            return SecurityResultFactory.Create();
        }
#pragma warning restore CA1031
    }
}
