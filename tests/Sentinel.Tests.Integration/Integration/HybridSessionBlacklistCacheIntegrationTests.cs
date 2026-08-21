using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.EntityFrameworkCore;
using Sentinel.EntityFrameworkCore.Models;
using Sentinel.EntityFrameworkCore.Stores;
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
    private MemoryCache _memoryCache = null!;
    private IOptions<MemoryCacheOptions> _memoryCacheOptions = null!;
    private RedisSessionBlacklistCache _redisCache = null!;
    private ConnectionMultiplexer? _redisConnection;
    private HybridSessionBlacklistCache _sut = null!;

    public async ValueTask InitializeAsync()
    {
        await Task.WhenAll(
            _postgresContainer.StartAsync(TestContext.Current.CancellationToken),
            _redisContainer.StartAsync(TestContext.Current.CancellationToken));

        var redisConfig = ConfigurationOptions.Parse(_redisContainer.GetConnectionString());
        _redisConnection = await ConnectionMultiplexer.ConnectAsync(redisConfig);

        var dbOptions = new DbContextOptionsBuilder<SentinelSecurityDbContext>()
            .UseNpgsql(_postgresContainer.GetConnectionString())
            .Options;

        await using (var context = new SentinelSecurityDbContext(dbOptions))
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

        _memoryCache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        _memoryCacheOptions = Options.Create(new MemoryCacheOptions { SizeLimit = 1000 });

        _sut = new HybridSessionBlacklistCache(
            _redisCache,
            NullLogger<HybridSessionBlacklistCache>.Instance,
            _dbContextFactory,
            TimeProvider.System,
            _redisOptions.KeyPrefix,
            _memoryCache,
            _memoryCacheOptions,
            redisMultiplexer: _redisConnection);
    }

    public async ValueTask DisposeAsync()
    {
        _sut.Dispose();

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

    [Fact(DisplayName =
        "✅ Write-Through: Session persists to real Postgres, propagates to Redis, and sets L1 revoked marker")]
    public async Task Production_WriteThrough_PersistsToPostgres_AndCachesInRedis_AndSetsL1Revoked()
    {
        // Arrange
        var sessionId = $"session-prod-{Guid.NewGuid():N}";
        var hashedId = ComputeSha256(sessionId);
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(15);

        // Act
        await _sut.BlacklistSessionAsync(sessionId, expiresAt, TestContext.Current.CancellationToken);

        // Assert
        var dbOptions = new DbContextOptionsBuilder<SentinelSecurityDbContext>()
            .UseNpgsql(_postgresContainer.GetConnectionString())
            .Options;

        await using (var dbContext = new SentinelSecurityDbContext(dbOptions))
        {
            var dbRecord = await dbContext.SessionBlacklist
                .SingleOrDefaultAsync(e => e.SessionId == hashedId, TestContext.Current.CancellationToken);

            dbRecord.Should().NotBeNull();
            dbRecord!.SessionId.Should().Be(hashedId);
        }

        var db = _redisConnection!.GetDatabase();
        var redisKey = $"test_blacklist:session:{hashedId}";
        var isCached = await db.KeyExistsAsync(redisKey);
        isCached.Should().BeTrue();

        // SECURITY INVARIANT: L1 stores a CONFIRMED revocation (fail-closed), never an "active" state.
        _memoryCache.TryGetValue($"revoked_session:{hashedId}", out _).Should().BeTrue();
        _memoryCache.TryGetValue($"active_session:{hashedId}", out _).Should().BeFalse();
    }

    [Fact(DisplayName =
        "❌ Fail-Closed Fast-Path: Locally confirmed revocation is rejected without touching Redis or PostgreSQL")]
    public async Task IsBlacklistedAsync_L1RevokedMarker_FailsClosed_WithoutRedisOrDb()
    {
        // Arrange
        var sessionId = $"session-revoked-{Guid.NewGuid():N}";
        var hashedId = ComputeSha256(sessionId);

        // Pre-populate the shared L1 with a CONFIRMED revocation.
        _memoryCache.Set($"revoked_session:{hashedId}", true, new MemoryCacheEntryOptions().SetSize(1));

        var crashingDbFactoryMock = new Mock<IDbContextFactory<SentinelSecurityDbContext>>(MockBehavior.Strict);
        var crashingRedisMock = new Mock<IRedisConnectionProvider>(MockBehavior.Strict);

        var localRedisCache = new RedisSessionBlacklistCache(
            crashingRedisMock.Object,
            _redisOptions,
            NullLogger<RedisSessionBlacklistCache>.Instance);

        using var sutWithBypass = new HybridSessionBlacklistCache(
            localRedisCache,
            NullLogger<HybridSessionBlacklistCache>.Instance,
            crashingDbFactoryMock.Object,
            TimeProvider.System,
            _redisOptions.KeyPrefix,
            _memoryCache,
            _memoryCacheOptions);

        // Act
        var result = await sutWithBypass.IsBlacklistedAsync(sessionId, TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeTrue("a locally confirmed revocation must fail closed without reaching L2/L3");
        Assert.False(_memoryCache.TryGetValue($"active_session:{hashedId}", out _),
            "L1 must never cache a positive 'session is active' decision.");
    }

    [Fact(DisplayName =
        "🔄 Read-Through Fallback: On Redis outage, system falls back to PostgreSQL and validates state")]
    public async Task Production_ReadThrough_FallbackToPostgres_DuringRedisOutage()
    {
        // Arrange
        var sessionId = $"session-fallback-{Guid.NewGuid():N}";
        var hashedId = ComputeSha256(sessionId);
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(30);

        var dbOptions = new DbContextOptionsBuilder<SentinelSecurityDbContext>()
            .UseNpgsql(_postgresContainer.GetConnectionString())
            .Options;

        await using (var dbContext = new SentinelSecurityDbContext(dbOptions))
        {
            dbContext.SessionBlacklist.Add(new SessionBlacklistEntry
            {
                SessionId = hashedId,
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

        // FIX: Wrap local test service instance in a using declaration to satisfy CA2000
        using var sutWithFallback = new HybridSessionBlacklistCache(
            brokenRedisCache,
            NullLogger<HybridSessionBlacklistCache>.Instance,
            _dbContextFactory,
            TimeProvider.System,
            _redisOptions.KeyPrefix,
            _memoryCache,
            _memoryCacheOptions);

        // Act
        var result = await sutWithFallback.IsBlacklistedAsync(sessionId, TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeTrue();
    }

    [Fact(DisplayName =
        "❌ Fail-Closed: When Redis write fails during revocation, throw SessionBlacklistUnavailableException")]
    public async Task Production_WriteThrough_ThrowsException_WhenRedisFails()
    {
        // Arrange
        var sessionId = $"session-failing-redis-{Guid.NewGuid():N}";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(15);

        var brokenConnectionProviderMock = new Mock<IRedisConnectionProvider>(MockBehavior.Strict);
        brokenConnectionProviderMock
            .Setup(p => p.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect,
                "Redis connection timed out"));

        var brokenRedisCache = new RedisSessionBlacklistCache(
            brokenConnectionProviderMock.Object,
            _redisOptions,
            NullLogger<RedisSessionBlacklistCache>.Instance);

        // FIX: Wrap local test service instance in a using declaration to satisfy CA2000
        using var sutWithFailingRedis = new HybridSessionBlacklistCache(
            brokenRedisCache,
            NullLogger<HybridSessionBlacklistCache>.Instance,
            _dbContextFactory,
            TimeProvider.System,
            _redisOptions.KeyPrefix,
            _memoryCache,
            _memoryCacheOptions);

        // Act
        var act = async () =>
            await sutWithFailingRedis.BlacklistSessionAsync(sessionId, expiresAt,
                TestContext.Current.CancellationToken);

        // Assert
        await act.Should().ThrowAsync<SessionBlacklistUnavailableException>()
            .WithMessage("Cache synchronization failed during session revocation. System is fail-closed.");
    }

    private static string ComputeSha256(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash);
    }
}
