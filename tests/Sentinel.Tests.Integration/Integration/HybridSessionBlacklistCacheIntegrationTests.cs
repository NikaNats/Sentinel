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

        if (_connectionProvider != null)
        {
            await _connectionProvider.DisposeAsync();
        }

        await Task.WhenAll(
            _postgresContainer.DisposeAsync().AsTask(),
            _redisContainer.DisposeAsync().AsTask());
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

    [Fact(DisplayName = "⚡ Fast-Path: When Redis is healthy, database query is bypassed completely on active requests")]
    public async Task IsBlacklistedAsync_WhenRedisIsHealthy_BypassesDatabaseQuery()
    {
        var crashingDbFactoryMock = new Mock<IDbContextFactory<SentinelSecurityDbContext>>(MockBehavior.Strict);

        var sutWithBypass = new HybridSessionBlacklistCache(
            _redisCache,
            NullLogger<HybridSessionBlacklistCache>.Instance,
            crashingDbFactoryMock.Object);

        var sessionId = $"session-bypass-{Guid.NewGuid():N}";

        var act = async () => await sutWithBypass.IsBlacklistedAsync(sessionId, TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync("Fast-Path must bypass PostgreSQL when Redis is online.");

        var result = await act();
        result.Should().BeFalse();
    }

    [Fact(DisplayName =
        "🔄 Read-Through Fallback: On Redis outage, system falls back to PostgreSQL and successfully recovers state")]
    public async Task Production_ReadThrough_FillsCacheOnMiss_DuringRedisOutage()
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
            _dbContextFactory);

        var result = await sutWithFallback.IsBlacklistedAsync(sessionId, TestContext.Current.CancellationToken);

        result.Should().BeTrue("The system must fall back to PostgreSQL and verify session revocation.");
    }

    [Fact(DisplayName =
        "🔴 Fail-Closed: Unexpected PostgreSQL exception during fallback must result in SessionBlacklistUnavailableException")]
    public async Task FailClosed_WhenPostgresThrowsUnexpectedException_ThrowsSessionBlacklistUnavailableException()
    {
        var brokenConnectionProviderMock = new Mock<IRedisConnectionProvider>(MockBehavior.Strict);
        brokenConnectionProviderMock
            .Setup(p => p.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "Redis offline"));

        var brokenRedisCache = new RedisSessionBlacklistCache(
            brokenConnectionProviderMock.Object,
            _redisOptions,
            NullLogger<RedisSessionBlacklistCache>.Instance);

        var brokenDbFactoryMock = new Mock<IDbContextFactory<SentinelSecurityDbContext>>(MockBehavior.Strict);
        brokenDbFactoryMock
            .Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("PostgreSQL cluster connection pool exhausted"));

        var brokenSut = new HybridSessionBlacklistCache(
            brokenRedisCache,
            NullLogger<HybridSessionBlacklistCache>.Instance,
            brokenDbFactoryMock.Object);

        var sessionId = $"session-fail-postgres-{Guid.NewGuid():N}";

        var act = async () => await brokenSut.IsBlacklistedAsync(sessionId, TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<SessionBlacklistUnavailableException>()
            .WithMessage("The system was unable to verify the session status.");
    }
}
