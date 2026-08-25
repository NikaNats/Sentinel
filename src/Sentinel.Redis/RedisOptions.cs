using System.Text.Json.Serialization;

namespace Sentinel.Redis;

/// <summary>
///     Configuration options for Redis and Redis Sentinel HA cache implementations.
/// </summary>
public sealed record RedisOptions
{
    /// <summary>
    ///     Redis connection endpoint(s).
    ///     Standalone format: "redis-master:6379"
    ///     Sentinel format: "sentinel-0:26379,sentinel-1:26379,sentinel-2:26379"
    /// </summary>
    public string? EndPoint { get; set; }

    /// <summary>
    ///     If configured, enables Redis Sentinel HA mode with automated master discovery and failover.
    ///     Example: "mymaster"
    /// </summary>
    public string? ServiceName { get; set; }

    /// <summary>
    ///     Whether to use SSL/TLS for Redis connections.
    /// </summary>
    public bool UseSsl { get; set; }

    /// <summary>
    ///     Redis Master and Replica authentication password.
    /// </summary>
    [JsonIgnore]
    public string? Password { get; set; }

    /// <summary>
    ///     Timeout for Redis operations (milliseconds).
    /// </summary>
    public int SyncTimeout { get; set; } = 3000;

    /// <summary>
    ///     Timeout for establishing connections (milliseconds).
    /// </summary>
    public int ConnectTimeout { get; set; } = 5000;

    /// <summary>
    ///     Prefix for Redis keys (e.g., "sentinel_prod:").
    /// </summary>
    public string KeyPrefix { get; set; } = "sentinel:";
}