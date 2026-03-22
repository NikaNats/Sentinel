namespace Sentinel.Session;

/// <summary>
/// Configuration for session management behavior.
/// </summary>
public sealed class SessionManagementOptions
{
    /// <summary>
    /// Configuration section name for appsettings.json.
    /// </summary>
    public const string SectionName = "SessionManagement";

    /// <summary>
    /// Gets or sets whether DPoP binding is required for sessions.
    /// If true, sessions track the DPoP thumbprint and validate it on each request.
    /// </summary>
    public bool RequireDpopBinding { get; set; } = true;

    /// <summary>
    /// Gets or sets the default session lifetime (seconds) if not specified by Keycloak.
    /// Typically 28800 (8 hours) or SsoSessionMaxLifespanSeconds from Keycloak config.
    /// </summary>
    public int SessionMaxLifetimeSeconds { get; set; } = 28800;

    /// <summary>
    /// Gets or sets the cleanup interval for expired session blacklist entries (seconds).
    /// Periodic cleanup prevents unbounded cache growth.
    /// </summary>
    public int BlacklistCleanupIntervalSeconds { get; set; } = 3600; // 1 hour
}
