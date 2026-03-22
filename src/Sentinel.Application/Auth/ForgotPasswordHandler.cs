using Microsoft.Extensions.Logging;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Domain.Auth;
using Sentinel.Security.Abstractions.Identity;

namespace Sentinel.Application.Auth;

public sealed class ForgotPasswordHandler(
    IIdentityProvider identityProvider,
    IResetTokenProvider resetTokenProvider,
    IEmailService emailService,
    ICaptchaService captchaService,
    ILogger<ForgotPasswordHandler> logger)
{
    public async Task HandleAsync(ForgotPasswordRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.CaptchaToken))
        {
            return;
        }

        if (!await captchaService.VerifyAsync(request.CaptchaToken, ct))
        {
            return;
        }

        try
        {
            var user = await identityProvider.GetUserByEmailAsync(request.Email.Trim(), ct);
            if (user is null)
            {
                return;
            }

            var token = resetTokenProvider.GenerateToken(request.Email.Trim());
            await emailService.SendResetPasswordEmailAsync(request.Email.Trim(), token, ct);
        }
#pragma warning disable CA1031 // Intentional catch-all: forgot-password endpoint must fail closed and keep anti-enumeration behavior.
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Forgot password processing failed for {Email}.", request.Email);
        }
#pragma warning restore CA1031
    }
}
