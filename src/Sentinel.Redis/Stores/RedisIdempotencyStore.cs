using Sentinel.Security.Abstractions.Idempotency;

namespace Sentinel.Redis.Stores;

/// <summary>
///     Redis-backed idempotency state store.
/// </summary>
public sealed class RedisIdempotencyStore(
    IRedisConnectionProvider provider,
    ILogger<RedisIdempotencyStore> logger) : IIdempotencyStore
{
    private const string InProgress = "IN_PROGRESS";
    private const string Completed = "COMPLETED";

    public async Task<IdempotencyAcquireResult> TryAcquireAsync(
        string key,
        TimeSpan inProgressTtl,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        try
        {
            var multiplexer = await provider.GetConnectionAsync(cancellationToken);
            var db = multiplexer.GetDatabase();

            var acquired = await db.StringSetAsync(
                key,
                InProgress,
                inProgressTtl,
                When.NotExists,
                CommandFlags.None);

            if (acquired)
            {
                return IdempotencyAcquireResult.Acquired;
            }

            var state = await db.StringGetAsync(key, CommandFlags.None);
            return string.Equals(state.ToString(), Completed, StringComparison.Ordinal)
                ? IdempotencyAcquireResult.Completed
                : IdempotencyAcquireResult.InProgress;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Redis unavailable during idempotency acquire for key {Key}.", key);
            throw new IdempotencyStoreUnavailableException(
                "Redis is unavailable; idempotency check failed.",
                ex);
        }
    }

    public async Task MarkCompletedAsync(string key, TimeSpan completedTtl, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        try
        {
            var multiplexer = await provider.GetConnectionAsync(cancellationToken);
            var db = multiplexer.GetDatabase();

            _ = await db.StringSetAsync(
                key,
                Completed,
                completedTtl,
                When.Always,
                CommandFlags.None);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Redis unavailable while marking idempotency key {Key} as completed.", key);
            throw new IdempotencyStoreUnavailableException(
                "Redis is unavailable; idempotency completion write failed.",
                ex);
        }
    }

    public async Task ReleaseAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        try
        {
            var multiplexer = await provider.GetConnectionAsync(cancellationToken);
            var db = multiplexer.GetDatabase();
            _ = await db.KeyDeleteAsync(key, CommandFlags.None);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Redis unavailable while releasing idempotency key {Key}.", key);
            throw new IdempotencyStoreUnavailableException(
                "Redis is unavailable; idempotency key release failed.",
                ex);
        }
    }
}
