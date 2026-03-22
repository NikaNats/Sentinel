namespace Sentinel.Security.Abstractions.Options;

/// <summary>
/// Configuration for Server-Sent Events (SSF / CAEP) processing.
/// </summary>
public sealed class SsfOptions
{
    /// <summary>
    /// Configuration section name for appsettings.json.
    /// </summary>
    public const string SectionName = "Ssf";

    /// <summary>
    /// Gets or sets whether SET processing is enabled.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Gets or sets the allowed clock skew for SET timestamp validation (seconds).
    /// </summary>
    public int AllowedClockSkewSeconds { get; init; } = 300;

    /// <summary>
    /// Gets or sets the set token lifetime (seconds).
    /// SET tokens older than this are rejected.
    /// </summary>
    public int SetTokenLifetimeSeconds { get; init; } = 3600;

    /// <summary>
    /// Gets or sets whether SSF webhook authentication is required.
    /// </summary>
    public bool RequireAuthToken { get; init; }

    /// <summary>
    /// Gets or sets the authentication token for SSF webhooks.
    /// </summary>
    public string? AuthToken { get; init; }
}
