using System.ComponentModel.DataAnnotations;

namespace Sentinel.Keycloak;

/// <summary>
///     Configuration options for Keycloak client connections.
/// </summary>
#pragma warning disable CA1056 // ServerUrl property is intentionally string for configuration binding
public sealed record KeycloakClientOptions
{
    /// <summary>
    ///     Keycloak server base URL (e.g., "http://localhost:8080").
    /// </summary>
    public Uri? ServerUri { get; set; }

    /// <summary>
    ///     Keycloak realm name (e.g., "sentinelbase").
    /// </summary>
    public string Realm { get; set; } = string.Empty;

    /// <summary>
    ///     Client ID for Sentinel application.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    ///     Client secret for authentication with Keycloak admin API.
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    ///     Allowed clock skew for token validation (seconds).
    /// </summary>
    public int AllowedClockSkewSeconds { get; set; } = 60;

    /// <summary>
    ///     Metadata cache duration (seconds).
    /// </summary>
    public int MetadataCacheDurationSeconds { get; set; } = 3600;

    /// <summary>
    ///     Connection timeout for HTTP requests to Keycloak (milliseconds).
    /// </summary>
    public int HttpTimeoutMs { get; set; } = 5000;

    /// <summary>
    ///     Gets the server URL as a string.
    /// </summary>
    public string ServerUrl => ServerUri?.ToString() ?? string.Empty;
}
#pragma warning restore CA1056

/// <summary>
///     Configuration options for Keycloak integration with Sentinel OAuth 2.0 server.
/// </summary>
public sealed class KeycloakOptions
{
    public const string SectionName = "Keycloak";

    [Required] [Url] public string Authority { get; set; } = string.Empty;

    [Required] public string Audience { get; set; } = string.Empty;

    public bool RequireHttpsMetadata { get; set; } = true;

    public int SsoSessionMaxLifespanSeconds { get; set; } = 28_800;

    public KeycloakAdminOptions Admin { get; set; } = new();
}

/// <summary>
///     Admin-specific options for Keycloak integration.
/// </summary>
public sealed class KeycloakAdminOptions
{
    public string ClientId { get; set; } = string.Empty;

    public string ClientSecret { get; set; } = string.Empty;

    public string? Scope { get; set; }
}
