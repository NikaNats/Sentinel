namespace Sentinel.Keycloak.Services;

using Sentinel.Keycloak.Models;

/// <summary>
/// Manages Keycloak user/subject operations via admin API.
/// </summary>
public sealed class KeycloakSubjectService
{
    private readonly KeycloakOptions _options;
    private readonly HttpClient _httpClient;
    private readonly KeycloakTokenService _tokenService;
    private readonly ILogger<KeycloakSubjectService> _logger;

    public KeycloakSubjectService(
        KeycloakOptions options,
        HttpClient httpClient,
        KeycloakTokenService tokenService,
        ILogger<KeycloakSubjectService> logger)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _tokenService = tokenService ?? throw new ArgumentNullException(nameof(tokenService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Gets subject details by user ID.
    /// </summary>
    public async Task<KeycloakSubject?> GetSubjectAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId, nameof(userId));

        try
        {
            var token = await _tokenService.GetAccessTokenAsync(cancellationToken);
            var serverUrl = _options.ServerUrl;
            if (string.IsNullOrWhiteSpace(serverUrl))
            {
                throw new InvalidOperationException("Keycloak ServerUri must be configured");
            }

            var url = $"{serverUrl}/admin/realms/{_options.Realm}/users/{userId}";

            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Failed to get subject with status {StatusCode}", response.StatusCode);
                return null;
            }

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            var subject = JsonSerializer.Deserialize<KeycloakSubject>(json);

            _logger.LogInformation("Subject retrieved: {UserId}", userId);
            return subject;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get subject: {UserId}", userId);
            throw;
        }
    }

    /// <summary>
    /// Revokes all user sessions (logout everywhere) for a subject.
    /// </summary>
    public async Task<bool> RevokeUserSessionsAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId, nameof(userId));

        try
        {
            var token = await _tokenService.GetAccessTokenAsync(cancellationToken);
            var serverUrl = _options.ServerUrl;
            if (string.IsNullOrWhiteSpace(serverUrl))
            {
                throw new InvalidOperationException("Keycloak ServerUri must be configured");
            }

            var url = $"{serverUrl}/admin/realms/{_options.Realm}/users/{userId}/logout";

            using var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            var response = await _httpClient.SendAsync(request, cancellationToken);
            var success = response.IsSuccessStatusCode;

            if (success)
            {
                _logger.LogInformation("User sessions revoked: {UserId}", userId);
            }
            else
            {
                _logger.LogWarning("Failed to revoke user sessions with status {StatusCode}", response.StatusCode);
            }

            return success;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to revoke user sessions: {UserId}", userId);
            throw;
        }
    }

    /// <summary>
    /// Disables a user account.
    /// </summary>
    public async Task<bool> DisableUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId, nameof(userId));

        try
        {
            var token = await _tokenService.GetAccessTokenAsync(cancellationToken);
            var serverUrl = _options.ServerUrl;
            if (string.IsNullOrWhiteSpace(serverUrl))
            {
                throw new InvalidOperationException("Keycloak ServerUri must be configured");
            }

            var url = $"{serverUrl}/admin/realms/{_options.Realm}/users/{userId}";

            var updatePayload = new { enabled = false };
            var json = JsonSerializer.Serialize(updatePayload);

            using var request = new HttpRequestMessage(HttpMethod.Put, url)
            {
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
            };
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            var response = await _httpClient.SendAsync(request, cancellationToken);
            var success = response.IsSuccessStatusCode;

            if (success)
            {
                _logger.LogInformation("User disabled: {UserId}", userId);
            }
            else
            {
                _logger.LogWarning("Failed to disable user with status {StatusCode}", response.StatusCode);
            }

            return success;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to disable user: {UserId}", userId);
            throw;
        }
    }
}
