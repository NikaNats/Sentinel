using System.Text.Json;
using Sentinel.Security.Abstractions.Idempotency;

namespace Sentinel.Redis.Stores;

public sealed class RedisIdempotencyStore(
    IRedisConnectionProvider provider,
    ILogger<RedisIdempotencyStore> logger) : IIdempotencyStore
{
    private const string InProgress = "IN_PROGRESS";
    private const int MaxAcquisitionAttempts = 3;

    public async Task<(IdempotencyAcquireResult State, CachedHttpResponse? Response)> TryAcquireAsync(
        string key,
        TimeSpan inProgressTtl,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var multiplexer = await provider.GetConnectionAsync(cancellationToken);
            var db = multiplexer.GetDatabase();

            for (var attempt = 1; attempt <= MaxAcquisitionAttempts; attempt++)
            {
                var acquired =
                    await db.StringSetAsync(key, InProgress, inProgressTtl, When.NotExists, CommandFlags.None);
                if (acquired)
                {
                    return (IdempotencyAcquireResult.Acquired, null);
                }

                var state = await db.StringGetAsync(key);
                if (state.IsNullOrEmpty)
                {
                    logger.LogWarning(
                        "Idempotency lock race detected for key {Key}. Retrying acquisition. Attempt {Attempt}/{Max}",
                        key, attempt, MaxAcquisitionAttempts);
                    continue;
                }

                if (state.ToString() == InProgress)
                {
                    return (IdempotencyAcquireResult.InProgress, null);
                }

                try
                {
                    var cached =
                        JsonSerializer.Deserialize(state.ToString(), RedisJsonContext.Default.CachedHttpResponse);
                    return (IdempotencyAcquireResult.Completed, cached);
                }
                catch (JsonException)
                {
                    return (IdempotencyAcquireResult.Completed, null);
                }
            }

            logger.LogCritical(
                "Idempotency lock acquisition exhausted all attempts due to extreme concurrency for key {Key}.", key);
            return (IdempotencyAcquireResult.InProgress, null);
        }
        catch (IdempotencyStoreUnavailableException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Redis unavailable during idempotency acquire for key {Key}.", key);
            throw new IdempotencyStoreUnavailableException("Redis is unavailable.", ex);
        }
    }

    public async Task MarkCompletedAsync(string key, CachedHttpResponse response, TimeSpan completedTtl,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var multiplexer = await provider.GetConnectionAsync(cancellationToken);
            var db = multiplexer.GetDatabase();

            var json = JsonSerializer.Serialize(response, RedisJsonContext.Default.CachedHttpResponse);

            await db.StringSetAsync(key, json, completedTtl, When.Always, CommandFlags.None);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Redis unavailable while marking idempotency key {Key} as completed.", key);
            throw new IdempotencyStoreUnavailableException("Redis is unavailable.", ex);
        }
    }

    public async Task ReleaseAsync(string key, CancellationToken cancellationToken = default)
    {
        try
        {
            var multiplexer = await provider.GetConnectionAsync(cancellationToken);
            var db = multiplexer.GetDatabase();
            await db.KeyDeleteAsync(key);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Redis unavailable while releasing idempotency key {Key}.", key);
            throw new IdempotencyStoreUnavailableException("Redis is unavailable.", ex);
        }
    }
}
