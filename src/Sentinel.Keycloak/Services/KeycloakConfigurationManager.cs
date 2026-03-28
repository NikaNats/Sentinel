using System.Text.Json;
using System.Net.Http.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Sentinel.Keycloak.Services;

/// <summary>
/// Manages Keycloak OpenID Connect configuration with thread-safe caching.
/// ✅ FIX: Uses SemaphoreSlim for thread safety, stores immutable Dictionary&lt;string, JsonElement&gt;
/// instead of disposable JsonDocument, uses TimeProvider for testability.
/// </summary>
public sealed class KeycloakConfigurationManager : IDisposable
{
    private readonly KeycloakOptions _options;
    private readonly HttpClient _httpClient;
    private readonly ILogger<KeycloakConfigurationManager> _logger;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _lock = new(1, 1);

    // ✅ FIX: Cache an immutable Dictionary (thread-safe), not a disposable JsonDocument
    private Dictionary<string, JsonElement>? _cachedConfig;
    private DateTimeOffset _expiry = DateTimeOffset.MinValue;

    public KeycloakConfigurationManager(
        IOptions<KeycloakOptions> options,
        HttpClient httpClient,
        ILogger<KeycloakConfigurationManager> logger,
        TimeProvider? timeProvider = null)
    {
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Gets the JWKS URI from the OpenID Connect configuration (with caching).
    /// </summary>
    public async Task<string?> GetJwksUriAsync(CancellationToken cancellationToken = default)
    {
        if (IsCacheValid() && _cachedConfig is not null)
        {
            _logger.LogDebug("Using cached JWKS URI from OpenID configuration");
            return ExtractJwksUri(_cachedConfig);
        }

        // ✅ FIX: Acquire lock to prevent concurrent requests/cache invalidation races
        await _lock.WaitAsync(cancellationToken);
        try
        {
            // Double-check cache after acquiring lock (classic double-check locking)
            if (IsCacheValid() && _cachedConfig is not null)
            {
                return ExtractJwksUri(_cachedConfig);
            }

            var authority = _options.Authority.TrimEnd('/');
            var discoveryUrl = $"{authority}/.well-known/openid-configuration";

            _logger.LogInformation("Fetching OpenID configuration from: {DiscoveryUrl}", discoveryUrl);

            var response = await _httpClient.GetAsync(discoveryUrl, cancellationToken);
            response.EnsureSuccessStatusCode();

            // ✅ FIX: Native AOT-safe deserialization using source-generated context
            _cachedConfig = await response.Content.ReadFromJsonAsync(
                KeycloakJsonContext.Default.DictionaryStringJsonElement, cancellationToken);

            if (_cachedConfig == null)
            {
                throw new InvalidOperationException("Failed to parse Keycloak OpenID configuration");
            }

            // Cache for 1 hour
            _expiry = _timeProvider.GetUtcNow().AddHours(1);

            _logger.LogInformation("Keycloak OpenID configuration loaded successfully");
            return ExtractJwksUri(_cachedConfig);
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Invalidates the cached configuration to force refresh on next request.
    /// </summary>
    public void InvalidateCache()
    {
        _expiry = DateTimeOffset.MinValue;
        _cachedConfig = null;
        _logger.LogInformation("Keycloak OpenID configuration cache invalidated");
    }

    private bool IsCacheValid() => _cachedConfig != null && _timeProvider.GetUtcNow() < _expiry;

    private static string? ExtractJwksUri(Dictionary<string, JsonElement> config)
    {
        if (config.TryGetValue("jwks_uri", out var jwksUri))
        {
            return jwksUri.GetString();
        }

        return null;
    }

    public void Dispose()
    {
        _lock.Dispose();
    }
}
