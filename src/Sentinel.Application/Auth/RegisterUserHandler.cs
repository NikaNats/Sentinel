using System.Security.Cryptography;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Domain.Users;
using Sentinel.Security.Abstractions.Identity;
using Sentinel.Security.Abstractions.Results;

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

    /// <summary>
    /// Handles user registration with Railway Oriented Programming pattern.
    /// Validates request → verifies captcha → validates password → creates user → sends verification email.
    /// </summary>
    public async Task<SecurityResult<RegisterUserResult>> HandleAsync(
        RegisterUserRequest request,
        string sourceIp,
        CancellationToken ct)
    {
        // Anti-timing attack: add random delay before validation
        await Task.Delay(RandomNumberGenerator.GetInt32(100, 301), ct);

        // Step 1: Validate request structure
        var validationResult = ValidateRequest(request);
        if (!validationResult.IsSuccess)
        {
            return SecurityResultFactory.Failure<RegisterUserResult>(validationResult.ErrorMessage!);
        }

        // Step 2: Verify captcha
        var captchaValid = await _captchaService.VerifyAsync(request.CaptchaToken, ct);
        if (!captchaValid)
        {
            return SecurityResultFactory.Failure<RegisterUserResult>(SecurityErrors.InvalidCaptchaMessage);
        }

        // Step 3: Validate password strength
        var passwordValidation = _passwordStrengthValidator.Validate(request.Password);
        if (!passwordValidation.IsValid)
        {
            return SecurityResultFactory.Failure<RegisterUserResult>(
                passwordValidation.Message ?? SecurityErrors.WeakPasswordMessage);
        }

        // Step 4: Create user identity
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

        var identityRegistration = new IdentityRegistration(
            registration.Email,
            registration.Username,
            registration.Consent.TermsAccepted,
            registration.Consent.PrivacyPolicyVersion,
            registration.Consent.AcceptedAtUtc,
            registration.Consent.IpAddress);

        var creationResult = await _identityRegistry.CreateUserAsync(
            identityRegistration,
            request.Password,
            ct);

        // If user already exists, maintain zero-knowledge principle: don't reveal if email is registered
        if (!creationResult.IsSuccess)
        {
            if (creationResult.ErrorMessage == SecurityErrors.IdentityConflictMessage)
            {
                await _emailService.SendWelcomeOrAlreadyRegisteredEmailAsync(registration.Email, ct);
                return SecurityResultFactory.Create(
                    new RegisterUserResult(
                        true,
                        "If this email is new, you'll receive a verification email."));
            }

            return SecurityResultFactory.Failure<RegisterUserResult>(creationResult.ErrorMessage!);
        }

        var keycloakUserId = creationResult.Value;

        // Step 5: Store verification token
        var verificationToken = Guid.NewGuid().ToString("N");
        var tokenStored = await _verificationTokenStore.StoreAsync(
            verificationToken,
            keycloakUserId,
            TimeSpan.FromHours(24),
            ct);

        if (!tokenStored)
        {
            return SecurityResultFactory.Failure<RegisterUserResult>(
                SecurityErrors.TokenStoreFailedMessage);
        }

        // Step 6: Send verification email
        try
        {
            await _emailService.SendVerificationEmailAsync(registration.Email, verificationToken, ct);
        }
        catch (InvalidOperationException ex)
        {
            return SecurityResultFactory.Failure<RegisterUserResult>(
                $"{SecurityErrors.EmailDeliveryFailedMessage}: {ex.Message}");
        }

        return SecurityResultFactory.Create(
            new RegisterUserResult(
                true,
                "If this email is new, you'll receive a verification email."));
    }

    /// <summary>
    /// Validates the incoming registration request (terms acceptance and required fields).
    /// </summary>
    private static SecurityResult<RegisterUserRequest> ValidateRequest(RegisterUserRequest request)
    {
        if (!request.AcceptTerms)
        {
            return SecurityResultFactory.Failure<RegisterUserRequest>(
                SecurityErrors.TermsNotAcceptedMessage);
        }

        if (string.IsNullOrWhiteSpace(request.Email)
            || string.IsNullOrWhiteSpace(request.Username)
            || string.IsNullOrWhiteSpace(request.Password)
            || string.IsNullOrWhiteSpace(request.CaptchaToken))
        {
            return SecurityResultFactory.Failure<RegisterUserRequest>(
                "Email, username, password and captcha token are required.");
        }

        return SecurityResultFactory.Create(request);
    }
}
