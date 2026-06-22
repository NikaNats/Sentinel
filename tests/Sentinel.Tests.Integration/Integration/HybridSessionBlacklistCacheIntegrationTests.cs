using FluentAssertions;
using Microsoft.EntityFrameworkCore;
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

/// <summary>
///     High-assurance integration test suite validating HybridSessionBlacklistCache behavior
///     against isolated PostgreSQL and Redis containers using Testcontainers.
///     Enforces write-through, read-through, and fail-closed resilience guarantees
///     in a production-like environment with real infrastructure dependencies.
/// </summary>
public sealed class HybridSessionBlacklistCacheIntegrationTests : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder("postgres:17-alpine")
        .WithDatabase("sentinel_integration_db")
        .WithUsername("postgres")
        .WithPassword("secure_password_123")
        .Build();

    private readonly RedisContainer _redisContainer = new RedisBuilder("redis:7.4-alpine")
        .Build();

    private IDbContextFactory<SentinelSecurityDbContext> _dbContextFactory = null!;
    private RedisSessionBlacklistCache _redisCache = null!;

    private ConnectionMultiplexer? _redisConnection;
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

        var redisOptions = new RedisOptions { KeyPrefix = "test_blacklist:" };
        var connectionProviderMock = new Mock<IRedisConnectionProvider>();
        connectionProviderMock.Setup(p => p.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(_redisConnection!);

        _redisCache = new RedisSessionBlacklistCache(
            connectionProviderMock.Object,
            redisOptions,
            NullLogger<RedisSessionBlacklistCache>.Instance);

        _sut = new HybridSessionBlacklistCache(
            _redisCache,
            NullLogger<HybridSessionBlacklistCache>.Instance,
            _dbContextFactory);
    }

    async ValueTask IAsyncDisposable.DisposeAsync()
    {
        if (_redisConnection != null)
        {
            await _redisConnection.DisposeAsync();
        }

        await _postgresContainer.DisposeAsync();
        await _redisContainer.DisposeAsync();
    }

    [Fact(DisplayName = "✅ Write-Through: Session successfully writes to real Postgres and propagates to real Redis")]
    public async Task Production_WriteThrough_PersistsToPostgres_AndCachesInRedis()
    {
        var sessionId = $"session-prod-{Guid.NewGuid():N}";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(15);

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
    }

    [Fact(DisplayName = "🔄 Read-Through: On cache miss in Redis, data is read from Postgres and written back to Redis")]
    public async Task Production_ReadThrough_FillsCacheOnMiss()
    {
        var sessionId = $"session-miss-{Guid.NewGuid():N}";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(30);

        var dbOptions = new DbContextOptionsBuilder<SentinelSecurityDbContext>()
            .UseNpgsql(_postgresContainer.GetConnectionString())
            .Options;

        using (var dbContext = new SentinelSecurityDbContext(dbOptions))
        {
            dbContext.SessionBlacklist.Add(new SessionBlacklistEntry
            {
                SessionId = sessionId,
                ExpiresAt = expiresAt,
                CreatedAt = DateTimeOffset.UtcNow
            });
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        var db = _redisConnection!.GetDatabase();
        var redisKey = $"test_blacklist:session:{sessionId}";
        (await db.KeyExistsAsync(redisKey)).Should().BeFalse();

        var result = await _sut.IsBlacklistedAsync(sessionId, TestContext.Current.CancellationToken);

        result.Should().BeTrue();

        var isCachedNow = await db.KeyExistsAsync(redisKey);
        isCachedNow.Should().BeTrue();
    }

    [Fact(DisplayName = "🔴 Fail-Closed: Any unexpected PostgreSQL exception must result in SessionBlacklistUnavailableException")]
    public async Task FailClosed_WhenPostgresThrowsUnexpectedException_ThrowsSessionBlacklistUnavailableException()
    {
        var brokenFactoryMock = new Mock<IDbContextFactory<SentinelSecurityDbContext>>();
        brokenFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Simulated critical DB connection failure"));

        var brokenSut = new HybridSessionBlacklistCache(
            _redisCache,
            NullLogger<HybridSessionBlacklistCache>.Instance,
            brokenFactoryMock.Object);

        var sessionId = $"session-fail-postgres-{Guid.NewGuid():N}";

        var act = async () => await brokenSut.IsBlacklistedAsync(sessionId, TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<SessionBlacklistUnavailableException>()
            .WithMessage("The system was unable to verify the session status.");
    }

    [Fact(DisplayName = "🔴 Fail-Closed: Redis failure when no database is configured must result in SessionBlacklistUnavailableException")]
    public async Task FailClosed_WhenRedisThrowsAndNoDbConfigured_ThrowsSessionBlacklistUnavailableException()
    {
        var brokenConnectionProviderMock = new Mock<IRedisConnectionProvider>();
        brokenConnectionProviderMock.Setup(p => p.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "Redis nodes are offline"));

        var brokenRedisCache = new RedisSessionBlacklistCache(
            brokenConnectionProviderMock.Object,
            new RedisOptions { KeyPrefix = "test_blacklist:" },
            NullLogger<RedisSessionBlacklistCache>.Instance);

        var brokenSut = new HybridSessionBlacklistCache(
            brokenRedisCache,
            NullLogger<HybridSessionBlacklistCache>.Instance,
            dbContextFactory: null);

        var sessionId = $"session-fail-redis-{Guid.NewGuid():N}";

        var act = async () => await brokenSut.IsBlacklistedAsync(sessionId, TestContext.Current.CancellationToken);
        await act.Should().ThrowAsync<SessionBlacklistUnavailableException>();
    }
}
