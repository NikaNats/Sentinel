using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.EntityFrameworkCore;
using Sentinel.EntityFrameworkCore.Models;
using Sentinel.Infrastructure.Cache;
using Sentinel.Redis;
using Sentinel.Redis.Stores;
using StackExchange.Redis;
using Testcontainers.PostgreSql;
using Testcontainers.Redis;

namespace Sentinel.Tests.Integration.Integration;

/// <summary>
///     High-assurance integration test.
///     Verifies the behavior of HybridSessionBlacklistCache against real, isolated
///     PostgreSQL and Redis containers (via Docker) using Testcontainers.
/// </summary>
public sealed class HybridSessionBlacklistCacheIntegrationTests : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder("postgres:16-alpine")
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

    /// <summary>
    ///     Explicit implementation of the IAsyncLifetime interface for startup initialization.
    /// </summary>
    async ValueTask IAsyncLifetime.InitializeAsync()
    {
        // 1. Start Docker containers in parallel (with CancellationToken support)
        await Task.WhenAll(
            _postgresContainer.StartAsync(TestContext.Current.CancellationToken),
            _redisContainer.StartAsync(TestContext.Current.CancellationToken));

        // 2. Connect to the dynamic Redis cluster
        var redisConfig = ConfigurationOptions.Parse(_redisContainer.GetConnectionString());
        _redisConnection = await ConnectionMultiplexer.ConnectAsync(redisConfig);

        // 3. Create the PostgreSQL DbContextFactory
        var dbOptions = new DbContextOptionsBuilder<SentinelSecurityDbContext>()
            .UseNpgsql(_postgresContainer.GetConnectionString())
            .Options;

        // Create the schema in the database (with CancellationToken support)
        using (var context = new SentinelSecurityDbContext(dbOptions))
        {
            await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        }

        var factoryMock = new Mock<IDbContextFactory<SentinelSecurityDbContext>>();
        factoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new SentinelSecurityDbContext(dbOptions));
        _dbContextFactory = factoryMock.Object;

        // 4. Configure services
        var redisOptions = new RedisOptions { KeyPrefix = "test_blacklist:" };
        var connectionProviderMock = new Mock<IRedisConnectionProvider>();
        connectionProviderMock.Setup(p => p.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(
                _redisConnection!); // Added null-forgiving operator to resolve nullability warnings in mock setup

        _redisCache = new RedisSessionBlacklistCache(
            connectionProviderMock.Object,
            redisOptions,
            NullLogger<RedisSessionBlacklistCache>.Instance);

        _sut = new HybridSessionBlacklistCache(
            _redisCache,
            NullLogger<HybridSessionBlacklistCache>.Instance,
            _dbContextFactory);
    }

    /// <summary>
    ///     Explicit implementation of IAsyncDisposable.DisposeAsync()
    /// </summary>
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
        // Arrange
        var sessionId = $"session-prod-{Guid.NewGuid():N}";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(15);

        // Act: Blacklist the session in the hybrid cache (using TestContext.Current.CancellationToken)
        await _sut.BlacklistSessionAsync(sessionId, expiresAt, TestContext.Current.CancellationToken);

        // Assert: 1. Verify that the data was physically written to the PostgreSQL database
        var dbOptions = new DbContextOptionsBuilder<SentinelSecurityDbContext>()
            .UseNpgsql(_postgresContainer.GetConnectionString())
            .Options;

        await using (var dbContext = new SentinelSecurityDbContext(dbOptions))
        {
            var dbRecord = await dbContext.SessionBlacklist
                .SingleOrDefaultAsync(e => e.SessionId == sessionId, TestContext.Current.CancellationToken);

            dbRecord.Should().NotBeNull("The record must exist in PostgreSQL");
            dbRecord!.SessionId.Should().Be(sessionId);
        }

        // Assert: 2. Verify that the data was instantly propagated to Redis
        var db = _redisConnection!.GetDatabase();
        var redisKey = $"test_blacklist:session:{sessionId}";
        var isCached = await db.KeyExistsAsync(redisKey);

        isCached.Should().BeTrue("The session must be cached in the real Redis instance as well (Write-Through)");
    }

    [Fact(DisplayName =
        "🔄 Read-Through: On cache miss in Redis, data is read from Postgres and written back to Redis")]
    public async Task Production_ReadThrough_FillsCacheOnMiss()
    {
        // Arrange
        var sessionId = $"session-miss-{Guid.NewGuid():N}";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(30);

        // 1. Write the data to PostgreSQL only
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

        // 2. Ensure that this key does not exist in Redis yet
        var db = _redisConnection!.GetDatabase();
        var redisKey = $"test_blacklist:session:{sessionId}";
        (await db.KeyExistsAsync(redisKey)).Should().BeFalse();

        // Act: Verify the session in the hybrid middleware (using TestContext.Current.CancellationToken)
        var result = await _sut.IsBlacklistedAsync(sessionId, TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeTrue();

        var isCachedNow = await db.KeyExistsAsync(redisKey);
        isCachedNow.Should()
            .BeTrue("After reading from PostgreSQL, the Redis cache must have been automatically populated");
    }
}
