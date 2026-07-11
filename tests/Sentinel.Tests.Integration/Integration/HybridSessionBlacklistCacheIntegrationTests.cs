using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.EntityFrameworkCore;
using Sentinel.EntityFrameworkCore.Models;
using Sentinel.Infrastructure.Cache;
using Sentinel.Redis;
using Sentinel.Redis.Stores;
using Sentinel.Security.Abstractions.Exceptions;
using StackExchange.Redis;
using Testcontainers.PostgreSql;
using Testcontainers.Redis;

namespace Sentinel.Tests.Integration.Integration;

public sealed class HybridSessionBlacklistCacheIntegrationTests : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder("postgres:17-alpine")
        .WithDatabase("sentinel_integration_db")
        .WithUsername("postgres")
        .WithPassword("secure_password_123")
        .Build();

    private readonly RedisContainer _redisContainer = new RedisBuilder("redis:7.4-alpine")
        .Build();

    private readonly RedisOptions _redisOptions = new() { KeyPrefix = "test_blacklist:" };
    private IRedisConnectionProvider _connectionProvider = null!;

    private IDbContextFactory<SentinelSecurityDbContext> _dbContextFactory = null!;
    private RedisSessionBlacklistCache _redisCache = null!;
    private ConnectionMultiplexer? _redisConnection;
    private MemoryCache _memoryCache = null!;
    private HybridSessionBlacklistCache _sut = null!;

    async ValueTask IAsyncLifetime.InitializeAsync()
    {
        await Task.WhenAll(
            _postgresContainer.StartAsync(TestContext.Current.CancellationToken),
            _redisContainer.StartAsync(TestContext.Current.CancellationToken));

        var redisConfig = ConfigurationOptions.Parse(_redisContainer.GetConnectionString());
        _redisConnection = await ConnectionMultiplexer.ConnectAsync(redisConfig);

        var dbOptions = new DbContextOptionsBuilder<SentinelSecurityDbContext>()
            .UseNpgsql(_postgresContainer.GetConnectionString())
            .Options;

        using (var context = new SentinelSecurityDbContext(dbOptions))
        {
            await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        }

        var factoryMock = new Mock<IDbContextFactory<SentinelSecurityDbContext>>();
        factoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new SentinelSecurityDbContext(dbOptions));
        _dbContextFactory = factoryMock.Object;

        var connectionProviderMock = new Mock<IRedisConnectionProvider>();
        connectionProviderMock.Setup(p => p.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(_redisConnection);
        _connectionProvider = connectionProviderMock.Object;

        _redisCache = new RedisSessionBlacklistCache(
            _connectionProvider,
            _redisOptions,
            NullLogger<RedisSessionBlacklistCache>.Instance);

        _memoryCache = new MemoryCache(new MemoryCacheOptions());

        _sut = new HybridSessionBlacklistCache(
            _redisCache,
            NullLogger<HybridSessionBlacklistCache>.Instance,
            _dbContextFactory,
            _memoryCache); // Passes concrete MemoryCache via IMemoryCache parameters
    }

    async ValueTask IAsyncDisposable.DisposeAsync()
    {
        if (_redisConnection != null)
        {
            await _redisConnection.DisposeAsync();
        }

        if (_connectionProvider != null)
        {
            await _connectionProvider.DisposeAsync();
        }

        _memoryCache.Dispose();

        await Task.WhenAll(
            _postgresContainer.DisposeAsync().AsTask(),
            _redisContainer.DisposeAsync().AsTask());
    }

    [Fact(DisplayName = "✅ Write-Through: Session successfully writes to real Postgres, propagates to Redis, and evicts L1")]
    public async Task Production_WriteThrough_PersistsToPostgres_AndCachesInRedis_AndClearsL1()
    {
        var sessionId = $"session-prod-{Guid.NewGuid():N}";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(15);

        _memoryCache.Set($"active_session:{sessionId}", true);

        await _sut.BlacklistSessionAsync(sessionId, expiresAt, TestContext.Current.CancellationToken);

        var dbOptions = new DbContextOptionsBuilder<SentinelSecurityDbContext>()
            .UseNpgsql(_postgresContainer.GetConnectionString())
            .Options;

        await using (var dbContext = new SentinelSecurityDbContext(dbOptions))
        {
            var dbRecord = await dbContext.SessionBlacklist
                .SingleOrDefaultAsync(e => e.SessionId == sessionId, TestContext.Current.CancellationToken);

            dbRecord.Should().NotBeNull();
            dbRecord!.SessionId.Should().Be(sessionId);
        }

        var db = _redisConnection!.GetDatabase();
        var redisKey = $"test_blacklist:session:{sessionId}";
        var isCached = await db.KeyExistsAsync(redisKey);
        isCached.Should().BeTrue();

        _memoryCache.TryGetValue($"active_session:{sessionId}", out _).Should().BeFalse();
    }

    [Fact(DisplayName = "⚡ Fast-Path: When session is active, subsequent checks bypass DB and Redis via L1 barrier")]
    public async Task IsBlacklistedAsync_BypassesDbAndRedis_ViaL1Barrier()
    {
        var crashingDbFactoryMock = new Mock<IDbContextFactory<SentinelSecurityDbContext>>(MockBehavior.Strict);
        var crashingRedisMock = new Mock<IRedisConnectionProvider>(MockBehavior.Strict);

        var localRedisCache = new RedisSessionBlacklistCache(
            crashingRedisMock.Object,
            _redisOptions,
            NullLogger<RedisSessionBlacklistCache>.Instance);

        var sutWithBypass = new HybridSessionBlacklistCache(
            localRedisCache,
            NullLogger<HybridSessionBlacklistCache>.Instance,
            crashingDbFactoryMock.Object,
            _memoryCache);

        var sessionId = $"session-bypass-{Guid.NewGuid():N}";

        var result1 = await _sut.IsBlacklistedAsync(sessionId, TestContext.Current.CancellationToken);
        result1.Should().BeFalse();

        var act = async () => await sutWithBypass.IsBlacklistedAsync(sessionId, TestContext.Current.CancellationToken);
        await act.Should().NotThrowAsync("L1 Memory Barrier must intercept and bypass database and cache.");

        var result2 = await act();
        result2.Should().BeFalse();
    }

    [Fact(DisplayName = "🔄 Read-Through Fallback: On Redis outage, system falls back to PostgreSQL and validates state")]
    public async Task Production_ReadThrough_FallbackToPostgres_DuringRedisOutage()
    {
        var sessionId = $"session-fallback-{Guid.NewGuid():N}";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(30);

        var dbOptions = new DbContextOptionsBuilder<SentinelSecurityDbContext>()
            .UseNpgsql(_postgresContainer.GetConnectionString())
            .Options;

        await using (var dbContext = new SentinelSecurityDbContext(dbOptions))
        {
            dbContext.SessionBlacklist.Add(new SessionBlacklistEntry
            {
                SessionId = sessionId,
                ExpiresAt = expiresAt,
                CreatedAt = DateTimeOffset.UtcNow
            });
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        var brokenConnectionProviderMock = new Mock<IRedisConnectionProvider>(MockBehavior.Strict);
        brokenConnectionProviderMock
            .Setup(p => p.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "Redis offline"));

        var brokenRedisCache = new RedisSessionBlacklistCache(
            brokenConnectionProviderMock.Object,
            _redisOptions,
            NullLogger<RedisSessionBlacklistCache>.Instance);

        var sutWithFallback = new HybridSessionBlacklistCache(
            brokenRedisCache,
            NullLogger<HybridSessionBlacklistCache>.Instance,
            _dbContextFactory,
            _memoryCache);

        var result = await sutWithFallback.IsBlacklistedAsync(sessionId, TestContext.Current.CancellationToken);
        result.Should().BeTrue();
    }
}
