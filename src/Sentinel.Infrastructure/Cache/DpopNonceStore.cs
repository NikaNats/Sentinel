using Sentinel.Application.Common.Abstractions;
using StackExchange.Redis;

namespace Sentinel.Infrastructure.Cache;

public sealed class DpopNonceStore(IConnectionMultiplexer redis, ILogger<DpopNonceStore> logger) : IDpopNonceStore
{
    private readonly IDatabase db = redis.GetDatabase();

    private static string GetKey(string thumbprint) => $"dpop:nonce:{thumbprint}";

    public async Task<string?> ConsumeNonceAsync(string thumbprint, CancellationToken ct)
    {
        try
        {
            var nonce = await db.StringGetDeleteAsync(GetKey(thumbprint));
            return nonce.HasValue ? nonce.ToString() : null;
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Failed to consume DPoP nonce from Redis.");
            throw new ReplayCacheUnavailableException("dpop nonce store unavailable", ex);
        }
    }

    public async Task StoreNonceAsync(string thumbprint, string nonce, TimeSpan ttl, CancellationToken ct)
    {
        try
        {
            await db.StringSetAsync(GetKey(thumbprint), nonce, ttl, When.Always);
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Failed to store DPoP nonce in Redis.");
            throw new ReplayCacheUnavailableException("dpop nonce store unavailable", ex);
        }
    }
}
