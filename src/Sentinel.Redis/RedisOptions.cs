namespace Sentinel.Redis;

using System.Text.Json.Serialization;

/// <summary>
/// Configuration options for Redis cache implementations.
/// </summary>
public sealed record RedisOptions
{
    /// <summary>
    /// Redis connection endpoint (e.g., "localhost:6379").
    /// </summary>
    public string? EndPoint { get; init; }

    /// <summary>
    /// Whether to use SSL for Redis connection.
    /// </summary>
    public bool UseSsl { get; init; }

    /// <summary>
    /// Redis password (basic auth).
    /// ✅ FIX: Prevent serialization of plaintext credentials in health checks or diagnostic dumps.
    /// </summary>
    [JsonIgnore]
    public string? Password { get; init; }

    /// <summary>
    /// Timeout for Redis operations (milliseconds).
    /// </summary>
    public int SyncTimeout { get; init; } = 5000;

    /// <summary>
    /// Prefix for Redis keys (e.g., "sentinel_dev:").
    /// </summary>
    public string KeyPrefix { get; init; } = "sentinel:";
}
