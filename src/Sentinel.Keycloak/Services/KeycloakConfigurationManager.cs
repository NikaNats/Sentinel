namespace Sentinel.Keycloak.Services;

/// <summary>
/// Manages Keycloak OpenID Connect configuration and token validation.
/// </summary>
public sealed class KeycloakConfigurationManager
{
    private readonly KeycloakClientOptions _options;
    private readonly HttpClient _httpClient;
    private readonly ILogger<KeycloakConfigurationManager> _logger;
    private JsonDocument? _cachedConfiguration;
    private DateTime _configurationExpiry = DateTime.MinValue;

    public KeycloakConfigurationManager(
        KeycloakClientOptions options,
        HttpClient httpClient,
        ILogger<KeycloakConfigurationManager> logger)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _httpClient.Timeout = TimeSpan.FromMilliseconds(options.HttpTimeoutMs);
    }

    /// <summary>
    /// Gets the current OpenID Connect configuration (with caching).
    /// </summary>
    public async Task<JsonDocument> GetConfigurationAsync(CancellationToken cancellationToken = default)
    {
        if (_cachedConfiguration != null && DateTime.UtcNow < _configurationExpiry)
        {
            _logger.LogDebug("Using cached Keycloak OIDC configuration");
            return _cachedConfiguration;
        }

        try
        {
            var serverUrl = _options.ServerUrl;
            if (string.IsNullOrWhiteSpace(serverUrl))
            {
                throw new InvalidOperationException("Keycloak ServerUri must be configured");
            }

            var discoveryUrl = $"{serverUrl}/realms/{_options.Realm}/.well-known/openid-configuration";
            _logger.LogInformation("Fetching Keycloak OIDC configuration from: {DiscoveryUrl}", discoveryUrl);

            var response = await _httpClient.GetAsync(discoveryUrl, cancellationToken);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            var config = JsonDocument.Parse(json);

            if (config == null)
            {
                throw new InvalidOperationException("Failed to parse Keycloak configuration");
            }

            _cachedConfiguration = config;
            _configurationExpiry = DateTime.UtcNow.AddSeconds(_options.MetadataCacheDurationSeconds);

            _logger.LogInformation("Keycloak OIDC configuration loaded successfully");
            return config;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to fetch Keycloak OIDC configuration");
            throw;
        }
    }

    /// <summary>
    /// Gets the JWKs (JSON Web Key Set) URL from the discovery endpoint.
    /// </summary>
    public async Task<string> GetJwksUriAsync(CancellationToken cancellationToken = default)
    {
        var config = await GetConfigurationAsync(cancellationToken);
        var root = config.RootElement;

        if (root.TryGetProperty("jwks_uri", out var jwksUri))
        {
            return jwksUri.GetString() ?? throw new InvalidOperationException("jwks_uri is null");
        }

        throw new InvalidOperationException("jwks_uri not found in Keycloak configuration");
    }

    /// <summary>
    /// Invalidates cached configuration to force refresh on next request.
    /// </summary>
    public void InvalidateCache()
    {
        _cachedConfiguration?.Dispose();
        _cachedConfiguration = null;
        _configurationExpiry = DateTime.MinValue;
        _logger.LogInformation("Keycloak OIDC configuration cache invalidated");
    }
}
