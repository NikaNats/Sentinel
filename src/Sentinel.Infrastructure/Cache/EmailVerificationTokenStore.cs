using Sentinel.Application.Auth.Interfaces;
using StackExchange.Redis;

namespace Sentinel.Infrastructure.Cache;

public sealed class EmailVerificationTokenStore(IConnectionMultiplexer redis) : IEmailVerificationTokenStore
{
    private readonly IDatabase db = redis.GetDatabase();

    public Task<bool> StoreAsync(string token, string keycloakUserId, TimeSpan ttl, CancellationToken ct)
    {
        return db.StringSetAsync(GetKey(token), keycloakUserId, ttl, When.NotExists);
    }

    public async Task<string?> ConsumeAsync(string token, CancellationToken ct)
    {
        var key = GetKey(token);
        var value = await db.StringGetDeleteAsync(key);
        return value.HasValue ? value.ToString() : null;
    }

    private static string GetKey(string token) => $"verify:email:{token}";
}
