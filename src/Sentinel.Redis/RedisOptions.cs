using System.Text.Json.Serialization;

namespace Sentinel.Redis;

/// <summary>
///     Configuration options for Redis cache implementations.
/// </summary>
public sealed record RedisOptions
{
    /// <summary>
    ///     Redis connection endpoint (e.g., "redis-master.redis.svc.cluster.local:6379").
    /// </summary>
    public string? EndPoint { get; set; }

    /// <summary>
    ///     Whether to use SSL for Redis connection.
    /// </summary>
    public bool UseSsl { get; set; }

    /// <summary>
    ///     Redis password (basic auth).
    /// </summary>
    [JsonIgnore]
    public string? Password { get; set; }

    /// <summary>
    ///     Timeout for Redis operations (milliseconds).
    /// </summary>
    public int SyncTimeout { get; set; } = 5000;

    /// <summary>
    ///     Prefix for Redis keys (e.g., "sentinel_prod:").
    /// </summary>
    public string KeyPrefix { get; set; } = "sentinel:";
}
