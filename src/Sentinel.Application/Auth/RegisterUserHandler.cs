using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Domain.Users;

namespace Sentinel.Application.Auth;

public sealed class RegisterUserHandler(
    ICaptchaService captchaService,
    IKeycloakAdminService keycloakAdminService,
    IEmailService emailService,
    IEmailVerificationTokenStore verificationTokenStore)
{
    public async Task<RegisterUserResult> HandleAsync(RegisterUserRequest request, string sourceIp, CancellationToken ct)
    {
        if (!request.AcceptTerms)
        {
            return new RegisterUserResult(false, "Terms must be accepted.", "terms_not_accepted");
        }

        if (string.IsNullOrWhiteSpace(request.Email)
            || string.IsNullOrWhiteSpace(request.Username)
            || string.IsNullOrWhiteSpace(request.Password)
            || string.IsNullOrWhiteSpace(request.CaptchaToken))
        {
            return new RegisterUserResult(false, "Email, username, password and captcha token are required.", "invalid_request");
        }

        if (!await captchaService.VerifyAsync(request.CaptchaToken, ct))
        {
            return new RegisterUserResult(false, "Invalid captcha.", "invalid_captcha");
        }

        var registration = new UserRegistration
        {
            Email = request.Email.Trim(),
            Username = request.Username.Trim(),
            Consent = new ConsentInfo(
                request.AcceptTerms,
                "v1.0",
                DateTime.UtcNow,
                sourceIp)
        };

        var keycloakUserId = await keycloakAdminService.CreateUserAsync(registration, request.Password, ct);
        var verificationToken = Guid.NewGuid().ToString("N");
        var stored = await verificationTokenStore.StoreAsync(verificationToken, keycloakUserId, TimeSpan.FromHours(24), ct);
        if (!stored)
        {
            return new RegisterUserResult(false, "Failed to create verification token.", "verification_token_store_failed");
        }

        await emailService.SendVerificationEmailAsync(registration.Email, verificationToken, ct);

        return new RegisterUserResult(true, "User created. Please verify email.");
    }
}
