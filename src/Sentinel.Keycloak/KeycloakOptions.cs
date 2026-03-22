namespace Sentinel.Keycloak;

/// <summary>
/// Configuration options for Keycloak integration.
/// </summary>
#pragma warning disable CA1056 // ServerUrl property is intentionally string for configuration binding
public sealed record KeycloakOptions
{
    /// <summary>
    /// Keycloak server base URL (e.g., "http://localhost:8080").
    /// </summary>
    public Uri? ServerUri { get; init; }

    /// <summary>
    /// Keycloak realm name (e.g., "sentinelbase").
    /// </summary>
    public string Realm { get; init; } = string.Empty;

    /// <summary>
    /// Client ID for Sentinel application.
    /// </summary>
    public string ClientId { get; init; } = string.Empty;

    /// <summary>
    /// Client secret for authentication with Keycloak admin API.
    /// </summary>
    public string ClientSecret { get; init; } = string.Empty;

    /// <summary>
    /// Allowed clock skew for token validation (seconds).
    /// </summary>
    public int AllowedClockSkewSeconds { get; init; } = 60;

    /// <summary>
    /// Metadata cache duration (seconds).
    /// </summary>
    public int MetadataCacheDurationSeconds { get; init; } = 3600;

    /// <summary>
    /// Connection timeout for HTTP requests to Keycloak (milliseconds).
    /// </summary>
    public int HttpTimeoutMs { get; init; } = 5000;

    /// <summary>
    /// Gets the server URL as a string.
    /// </summary>
    public string ServerUrl => ServerUri?.ToString() ?? string.Empty;
}
#pragma warning restore CA1056
