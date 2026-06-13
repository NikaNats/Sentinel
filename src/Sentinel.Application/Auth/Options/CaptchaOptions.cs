using System.ComponentModel.DataAnnotations;

namespace Sentinel.Application.Auth.Options;

public sealed record CaptchaOptions
{
    public const string SectionName = "Sentinel:Security:Captcha";

    public bool Enabled { get; init; } = true;

    [Required(ErrorMessage = "CAPTCHA secret key is required.")]
    public string SecretKey { get; init; } = string.Empty;

    [Required(ErrorMessage = "Verification URL is required.")]
    public Uri VerificationUrl { get; init; } = new("https://challenges.cloudflare.com/turnstile/v0/siteverify", UriKind.Absolute);

    [Range(1, 30, ErrorMessage = "Timeout must be between 1 and 30 seconds.")]
    public int TimeoutSeconds { get; init; } = 5;
}
