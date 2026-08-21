using Sentinel.Security.Abstractions.Token;
using StackExchange.Redis;

namespace Sentinel.Redis.Stores;

/// <summary>
///     Redis-backed adapter for the <see cref="IEmailVerificationTokenStore" /> port.
///     Enforces single-use semantics via atomic GETDEL and TTL enforcement via native
///     key expiration, keeping verification tokens out of persistent storage.
/// </summary>
public sealed class EmailVerificationTokenStore(IConnectionMultiplexer redis) : IEmailVerificationTokenStore
{
    private readonly IDatabase db = redis.GetDatabase();

    /// <inheritdoc />
    public Task<bool> StoreAsync(string token, string keycloakUserId, TimeSpan ttl, CancellationToken ct)
    {
        return db.StringSetAsync(GetKey(token), keycloakUserId, ttl, When.NotExists);
    }

    /// <inheritdoc />
    public async Task<string?> ConsumeAsync(string token, CancellationToken ct)
    {
        var key = GetKey(token);
        var value = await db.StringGetDeleteAsync(key);
        return value.HasValue ? value.ToString() : null;
    }

    private static string GetKey(string token) => $"verify:email:{token}";
}
