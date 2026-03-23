using System.Net.Http.Json;

namespace Sentinel.Security.Captcha;

public sealed class TurnstileService(HttpClient httpClient, IOptions<CaptchaOptions> options) : ICaptchaService
{
    public async Task<bool> VerifyAsync(string token, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(options.Value.SecretKey))
        {
            return false;
        }

        var response = await httpClient.PostAsJsonAsync(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            new { secret = options.Value.SecretKey, response = token },
            ct);

        if (!response.IsSuccessStatusCode)
        {
            return false;
        }

        var result = await response.Content.ReadFromJsonAsync<TurnstileVerifyResponse>(ct);
        return result?.Success ?? false;
    }

    private sealed record TurnstileVerifyResponse(bool Success);
}
