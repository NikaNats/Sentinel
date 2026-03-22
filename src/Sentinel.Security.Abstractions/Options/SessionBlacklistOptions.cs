namespace Sentinel.Security.Abstractions.Options;

/// <summary>
/// Configuration for session blacklist caching.
/// </summary>
public sealed class SessionBlacklistOptions
{
    /// <summary>
    /// Configuration section name for appsettings.json.
    /// </summary>
    public const string SectionName = "SessionBlacklist";

    /// <summary>
    /// Gets or sets the Redis key prefix for blacklist entries.
    /// </summary>
    public string KeyPrefix { get; set; } = "blacklist:sid:";

    /// <summary>
    /// Gets or sets the default TTL for blacklist entries (seconds).
    /// Typically set to the max token lifetime + grace period.
    /// </summary>
    public int DefaultTtlSeconds { get; set; } = 3600; // 1 hour
}
