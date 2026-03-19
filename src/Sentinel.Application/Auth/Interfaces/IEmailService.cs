namespace Sentinel.Application.Auth.Interfaces;

public interface IEmailService
{
    Task SendVerificationEmailAsync(string email, string verificationToken, CancellationToken ct);
    Task SendResetPasswordEmailAsync(string email, string resetToken, CancellationToken ct);
    Task SendWelcomeOrAlreadyRegisteredEmailAsync(string email, CancellationToken ct);
}
