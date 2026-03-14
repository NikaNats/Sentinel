using Sentinel.Application.Common.Abstractions;
using StackExchange.Redis;

namespace Sentinel.Infrastructure.Cache;

public sealed class DpopNonceStore(IConnectionMultiplexer redis, ILogger<DpopNonceStore> logger) : IDpopNonceStore
{
    private readonly IDatabase db = redis.GetDatabase();

    private static string GetKey(string thumbprint) => $"dpop:nonce:{thumbprint}";

    public async Task<string?> GetNonceAsync(string thumbprint, CancellationToken ct)
    {
        try
        {
            var nonce = await db.StringGetAsync(GetKey(thumbprint));
            return nonce.HasValue ? nonce.ToString() : null;
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Failed to read DPoP nonce from Redis.");
            throw new ReplayCacheUnavailableException("dpop nonce store unavailable", ex);
        }
    }

    public async Task<bool> TryStoreNonceAsync(string thumbprint, string nonce, TimeSpan ttl, CancellationToken ct)
    {
        try
        {
            return await db.StringSetAsync(GetKey(thumbprint), nonce, ttl, When.NotExists);
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Failed to store DPoP nonce in Redis.");
            throw new ReplayCacheUnavailableException("dpop nonce store unavailable", ex);
        }
    }

    public async Task<bool> ConsumeNonceIfMatchesAsync(string thumbprint, string expectedNonce, CancellationToken ct)
    {
        try
        {
            var key = GetKey(thumbprint);
            var tx = db.CreateTransaction();
            tx.AddCondition(Condition.StringEqual(key, expectedNonce));
            _ = tx.KeyDeleteAsync(key);
            return await tx.ExecuteAsync();
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Failed to consume DPoP nonce from Redis.");
            throw new ReplayCacheUnavailableException("dpop nonce store unavailable", ex);
        }
    }
}
