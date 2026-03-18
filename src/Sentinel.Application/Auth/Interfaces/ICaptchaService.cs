namespace Sentinel.Application.Auth.Interfaces;

public interface ICaptchaService
{
    Task<bool> VerifyAsync(string token, CancellationToken ct);
}
