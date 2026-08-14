using Microsoft.Extensions.DependencyInjection;
using Sentinel.Redis.Extensions;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;
using StackExchange.Redis;
using Testcontainers.Redis;

namespace Sentinel.Contracts.Redis;

/// <summary>
///     Contract fixture: boots a REAL Redis 7.4 server (the compose-pinned
///     image line) and wires the actual Sentinel.Redis stores through their
///     public DI extension. Contracts are pinned against the real Lua scripts
///     embedded in the stores — no re-implemented copies.
/// </summary>
public sealed class RedisContractFixture : IAsyncLifetime
{
    private readonly RedisContainer _redis;

    public RedisContractFixture()
    {
        _redis = new RedisBuilder("redis:7.4-alpine")
            .Build();
    }

    public string ConnectionString { get; private set; } = string.Empty;

    public ServiceProvider ProviderA { get; private set; } = null!;

    public ServiceProvider ProviderB { get; private set; } = null!;

    /// <summary>Raw StackExchange.Redis access for primitive-level pins (SET NX, scripts).</summary>
    public IConnectionMultiplexer RawMultiplexer { get; private set; } = null!;

    public IDatabase RawDatabase => RawMultiplexer.GetDatabase();

    public async ValueTask InitializeAsync()
    {
        await _redis.StartAsync();
        ConnectionString = _redis.GetConnectionString();

        ProviderA = Build("sentinel-contract-a:");
        ProviderB = Build("sentinel-contract-b:");
        RawMultiplexer = await ConnectionMultiplexer.ConnectAsync(ConnectionString);
    }

    public async ValueTask DisposeAsync()
    {
        RawMultiplexer.Dispose();
        await ProviderA.DisposeAsync();
        await ProviderB.DisposeAsync();
        await _redis.DisposeAsync();
    }

    public ServiceProvider Build(string keyPrefix)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddRedisSecurityCaches(options =>
        {
            options.EndPoint = ConnectionString;
            options.KeyPrefix = keyPrefix;
            options.SyncTimeout = 5000;
        });
        return services.BuildServiceProvider();
    }

    public static IDpopNonceStore NonceStore(ServiceProvider provider)
        => provider.GetRequiredService<IDpopNonceStore>();

    public static IJtiReplayCache JtiCache(ServiceProvider provider)
        => provider.GetRequiredService<IJtiReplayCache>();
}

[CollectionDefinition(Name)]
public sealed class RedisContractCollection : ICollectionFixture<RedisContractFixture>
{
    public const string Name = "Redis Contract";
}