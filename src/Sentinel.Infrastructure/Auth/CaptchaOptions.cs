namespace Sentinel.Infrastructure.Auth;

public sealed class CaptchaOptions
{
    public string SecretKey { get; set; } = string.Empty;
}
