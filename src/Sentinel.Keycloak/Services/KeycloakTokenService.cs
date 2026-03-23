namespace Sentinel.Keycloak.Services;

using Sentinel.Keycloak.Models;

/// <summary>
/// Manages Keycloak token lifecycle operations.
/// </summary>
public sealed class KeycloakTokenService
{
    private readonly KeycloakClientOptions _options;
    private readonly HttpClient _httpClient;
    private readonly ILogger<KeycloakTokenService> _logger;
    private KeycloakToken? _cachedToken;
    private DateTime _tokenExpiry = DateTime.MinValue;

    public KeycloakTokenService(
        KeycloakClientOptions options,
        HttpClient httpClient,
        ILogger<KeycloakTokenService> logger)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _httpClient.Timeout = TimeSpan.FromMilliseconds(options.HttpTimeoutMs);
    }

    /// <summary>
    /// Gets a valid access token for Sentinel admin operations (with caching and refresh).
    /// </summary>
    public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        // Return cached token if still valid
        if (_cachedToken != null && DateTime.UtcNow < _tokenExpiry.AddSeconds(-60))
        {
            _logger.LogDebug("Using cached Keycloak access token");
            return _cachedToken.AccessToken;
        }

        try
        {
            var serverUrl = _options.ServerUrl;
            if (string.IsNullOrWhiteSpace(serverUrl))
            {
                throw new InvalidOperationException("Keycloak ServerUri must be configured");
            }

            var tokenUrl = $"{serverUrl}/realms/{_options.Realm}/protocol/openid-connect/token";

            using var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "client_id", _options.ClientId },
                    { "client_secret", _options.ClientSecret },
                    { "grant_type", "client_credentials" }
                })
            };

            var response = await _httpClient.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            var token = JsonSerializer.Deserialize<KeycloakToken>(json);

            if (token == null || string.IsNullOrWhiteSpace(token.AccessToken))
            {
                throw new InvalidOperationException("Failed to deserialize Keycloak token response");
            }

            _cachedToken = token;
            _tokenExpiry = DateTime.UtcNow.AddSeconds(token.ExpiresIn);

            _logger.LogInformation("Obtained new Keycloak access token (expires in {ExpiresIn}s)", token.ExpiresIn);
            return token.AccessToken;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to obtain Keycloak access token");
            throw;
        }
    }

    /// <summary>
    /// Refreshes a user's refresh token.
    /// </summary>
    public async Task<KeycloakToken?> RefreshUserTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshToken, nameof(refreshToken));

        try
        {
            var serverUrl = _options.ServerUrl;
            if (string.IsNullOrWhiteSpace(serverUrl))
            {
                throw new InvalidOperationException("Keycloak ServerUri must be configured");
            }

            var tokenUrl = $"{serverUrl}/realms/{_options.Realm}/protocol/openid-connect/token";

            using var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "client_id", _options.ClientId },
                    { "client_secret", _options.ClientSecret },
                    { "grant_type", "refresh_token" },
                    { "refresh_token", refreshToken }
                })
            };

            var response = await _httpClient.SendAsync(request, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Token refresh failed with status {StatusCode}", response.StatusCode);
                return null;
            }

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            var token = JsonSerializer.Deserialize<KeycloakToken>(json);

            _logger.LogInformation("User token refreshed successfully");
            return token;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to refresh user token");
            throw;
        }
    }
}
