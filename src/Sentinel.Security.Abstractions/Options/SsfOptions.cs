namespace Sentinel.Security.Abstractions.Options;

/// <summary>
///     Configuration for Server-Sent Events (SSF / CAEP) processing.
/// </summary>
public sealed class SsfOptions
{
    /// <summary>
    ///     Configuration section name for appsettings.json.
    /// </summary>
    public const string SectionName = "Ssf";

    /// <summary>
    ///     Gets or sets whether SET processing is enabled. Off by default: the receiver is an anonymous
    ///     public webhook, so hosts opt in explicitly (and should also set <see cref="RequireAuthToken" />).
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    ///     Gets or sets the allowed clock skew for SET timestamp validation (seconds).
    /// </summary>
    public int AllowedClockSkewSeconds { get; set; } = 300;

    /// <summary>
    ///     Gets or sets the set token lifetime (seconds).
    ///     SET tokens older than this are rejected.
    /// </summary>
    public int SetTokenLifetimeSeconds { get; set; } = 3600;

    /// <summary>
    ///     Gets or sets whether SSF webhook authentication is required.
    /// </summary>
    public bool RequireAuthToken { get; set; }

    /// <summary>
    ///     Gets or sets the authentication token for SSF webhooks.
    /// </summary>
    public string? AuthToken { get; set; }
}
