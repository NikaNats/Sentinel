namespace Sentinel.Application.Auth.Interfaces;

public interface IEmailService
{
    Task SendVerificationEmailAsync(string email, string verificationToken, CancellationToken ct);
}
