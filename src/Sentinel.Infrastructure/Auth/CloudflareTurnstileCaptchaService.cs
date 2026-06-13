using System.Net.Http.Json;
using System.Text.Json;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Options;
using Sentinel.Infrastructure.Auth.Json;

namespace Sentinel.Infrastructure.Auth;

internal sealed class CloudflareTurnstileCaptchaService(
    HttpClient httpClient,
    IOptions<CaptchaOptions> options,
    ILogger<CloudflareTurnstileCaptchaService> logger)
    : ICaptchaService
{
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    private readonly ILogger<CloudflareTurnstileCaptchaService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    private readonly CaptchaOptions _options = options?.Value ?? throw new ArgumentNullException(nameof(options));

    public async Task<bool> VerifyAsync(string token, CancellationToken ct)
    {
        if (!_options.Enabled)
        {
            _logger.LogInformation("CAPTCHA validation is disabled via configuration.");
            return true;
        }

        if (string.IsNullOrWhiteSpace(token))
        {
            _logger.LogWarning("CAPTCHA validation failed: token is empty.");
            return false;
        }

        try
        {
            using var postData = new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("secret", _options.SecretKey),
                new KeyValuePair<string, string>("response", token)
            ]);

            using var response = await _httpClient.PostAsync("", postData, ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to connect to CAPTCHA provider. Status: {StatusCode}",
                    (int)response.StatusCode);
                return false;
            }

            var result = await response.Content.ReadFromJsonAsync(
                CaptchaJsonContext.Default.TurnstileResponse,
                ct).ConfigureAwait(false);

            if (result is null || !result.Success)
            {
                var errors = result?.ErrorCodes != null ? string.Join(", ", result.ErrorCodes) : "unknown error";
                _logger.LogWarning("CAPTCHA validation rejected by Cloudflare. Errors: {Errors}", errors);
                return false;
            }

            _logger.LogInformation("CAPTCHA validation completed successfully. Hostname: {Hostname}", result.Hostname);
            return true;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException ex)
        {
            _logger.LogError(ex, "CAPTCHA validation failed due to request timeout (Fail-Closed).");
            return false;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Network error while connecting to CAPTCHA server (Fail-Closed).");
            return false;
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Failed to deserialize CAPTCHA response format (Fail-Closed).");
            return false;
        }
    }
}
