using System.Security.Cryptography;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Domain.Users;
using Sentinel.Security.Abstractions.Identity;

namespace Sentinel.Application.Auth;

public sealed class RegisterUserHandler
{
    private readonly ICaptchaService _captchaService;
    private readonly IIdentityRegistry _identityRegistry;
    private readonly IEmailService _emailService;
    private readonly IEmailVerificationTokenStore _verificationTokenStore;
    private readonly IPasswordStrengthValidator _passwordStrengthValidator;
    private readonly TimeProvider _timeProvider;

    public RegisterUserHandler(
        ICaptchaService captchaService,
        IIdentityRegistry identityRegistry,
        IEmailService emailService,
        IEmailVerificationTokenStore verificationTokenStore,
        IPasswordStrengthValidator passwordStrengthValidator,
        TimeProvider? timeProvider = null)
    {
        _captchaService = captchaService;
        _identityRegistry = identityRegistry;
        _emailService = emailService;
        _verificationTokenStore = verificationTokenStore;
        _passwordStrengthValidator = passwordStrengthValidator;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<RegisterUserResult> HandleAsync(RegisterUserRequest request, string sourceIp,
        CancellationToken ct)
    {
        await Task.Delay(RandomNumberGenerator.GetInt32(100, 301), ct);

        if (!request.AcceptTerms)
        {
            return new RegisterUserResult(false, "Terms must be accepted.", "terms_not_accepted");
        }

        if (string.IsNullOrWhiteSpace(request.Email)
            || string.IsNullOrWhiteSpace(request.Username)
            || string.IsNullOrWhiteSpace(request.Password)
            || string.IsNullOrWhiteSpace(request.CaptchaToken))
        {
            return new RegisterUserResult(false, "Email, username, password and captcha token are required.",
                "invalid_request");
        }

        if (!await _captchaService.VerifyAsync(request.CaptchaToken, ct))
        {
            return new RegisterUserResult(false, "Invalid captcha.", "invalid_captcha");
        }

        var passwordValidation = _passwordStrengthValidator.Validate(request.Password);
        if (!passwordValidation.IsValid)
        {
            return new RegisterUserResult(false,
                passwordValidation.Message ?? "Password does not meet complexity requirements.",
                passwordValidation.ErrorCode ?? "weak_password");
        }

        var registration = new UserRegistration
        {
            Email = request.Email.Trim(),
            Username = request.Username.Trim(),
            Consent = new ConsentInfo(
                request.AcceptTerms,
                "v1.0",
                _timeProvider.GetUtcNow().DateTime,
                sourceIp)
        };

        string keycloakUserId;
        try
        {
            var identityRegistration = new IdentityRegistration(
                registration.Email,
                registration.Username,
                registration.Consent.TermsAccepted,
                registration.Consent.PrivacyPolicyVersion,
                registration.Consent.AcceptedAtUtc,
                registration.Consent.IpAddress);

            keycloakUserId = await _identityRegistry.CreateUserAsync(identityRegistration, request.Password, ct);
        }
        catch (UserAlreadyExistsException)
        {
            await _emailService.SendWelcomeOrAlreadyRegisteredEmailAsync(registration.Email, ct);
            return new RegisterUserResult(true, "If this email is new, you'll receive a verification email.");
        }

        var verificationToken = Guid.NewGuid().ToString("N");
        var stored =
            await _verificationTokenStore.StoreAsync(verificationToken, keycloakUserId, TimeSpan.FromHours(24), ct);
        if (!stored)
        {
            return new RegisterUserResult(false, "Failed to create verification token.",
                "verification_token_store_failed");
        }

        await _emailService.SendVerificationEmailAsync(registration.Email, verificationToken, ct);

        return new RegisterUserResult(true, "If this email is new, you'll receive a verification email.");
    }
}
