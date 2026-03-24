using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.EntityFrameworkCore;
using Sentinel.EntityFrameworkCore.Stores;
using FluentAssertions;

namespace Sentinel.Tests.Unit;

public sealed class EfJtiReplayCacheTests
{
    private readonly DbContextOptions<SentinelSecurityDbContext> _dbOptions;

    public EfJtiReplayCacheTests()
    {
        // Use in-memory SQLite database for testing
        _dbOptions = new DbContextOptionsBuilder<SentinelSecurityDbContext>()
            .UseSqlite("DataSource=:memory:")
            .Options;

        // Ensure database is created
        using var context = new SentinelSecurityDbContext(_dbOptions);
        context.Database.OpenConnection();
        context.Database.EnsureCreated();
    }

    private SentinelSecurityDbContext CreateDbContext()
    {
        return new SentinelSecurityDbContext(_dbOptions);
    }

    [Fact]
    public async Task TryMarkUsedAsync_WhenJtiIsNew_ReturnsTrue()
    {
        // Arrange
        using var context = CreateDbContext();
        var sut = new EfJtiReplayCache(
            CreateDbContextFactory(),
            NullLogger<EfJtiReplayCache>.Instance);
        
        var jti = Guid.NewGuid().ToString();
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        // Act
        var result = await sut.TryMarkUsedAsync(jti, expiresAt);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task TryMarkUsedAsync_WhenJtiAlreadyExists_CatchesDbUpdateException_ReturnsFalse()
    {
        // Arrange
        var sut = new EfJtiReplayCache(
            CreateDbContextFactory(),
            NullLogger<EfJtiReplayCache>.Instance);
        
        var jti = Guid.NewGuid().ToString();
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        // Act - Insert first time
        var firstResult = await sut.TryMarkUsedAsync(jti, expiresAt);
        
        // Act - Insert second time (simulating a replay attack)
        var secondResult = await sut.TryMarkUsedAsync(jti, expiresAt);

        // Assert - First should succeed, second should fail
        firstResult.Should().BeTrue("First insertion should succeed");
        secondResult.Should().BeFalse("Duplicate JTI should be rejected as replay");
    }

    [Fact]
    public async Task TryMarkUsedAsync_WithNullJti_ThrowsArgumentException()
    {
        // Arrange
        var sut = new EfJtiReplayCache(
            CreateDbContextFactory(),
            NullLogger<EfJtiReplayCache>.Instance);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(
            () => sut.TryMarkUsedAsync(null!, DateTimeOffset.UtcNow.AddMinutes(5)));
    }

    [Fact]
    public async Task TryMarkUsedAsync_WithEmptyJti_ThrowsArgumentException()
    {
        // Arrange
        var sut = new EfJtiReplayCache(
            CreateDbContextFactory(),
            NullLogger<EfJtiReplayCache>.Instance);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(
            () => sut.TryMarkUsedAsync("", DateTimeOffset.UtcNow.AddMinutes(5)));
    }

    [Fact]
    public async Task TryMarkUsedAsync_WithValidJti_InsertsIntoDatabase()
    {
        // Arrange
        var sut = new EfJtiReplayCache(
            CreateDbContextFactory(),
            NullLogger<EfJtiReplayCache>.Instance);
        
        var jti = Guid.NewGuid().ToString();
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        // Act
        await sut.TryMarkUsedAsync(jti, expiresAt);

        // Assert - Verify it's in the database
        using var context = CreateDbContext();
        var entry = await context.JtiReplayCache.FindAsync(jti);
        entry.Should().NotBeNull();
        entry!.Jti.Should().Be(jti);
    }

    [Fact]
    public async Task CleanupExpiredAsync_RemovesExpiredEntries()
    {
        // Arrange
        var sut = new EfJtiReplayCache(
            CreateDbContextFactory(),
            NullLogger<EfJtiReplayCache>.Instance);

        // Insert an expired entry and a future entry
        var expiredJti = Guid.NewGuid().ToString();
        var futureJti = Guid.NewGuid().ToString();
        
        await sut.TryMarkUsedAsync(expiredJti, DateTimeOffset.UtcNow.AddMinutes(-5)); // Expired
        await sut.TryMarkUsedAsync(futureJti, DateTimeOffset.UtcNow.AddMinutes(5));   // Future

        // Act
        await sut.CleanupExpiredAsync();

        // Assert
        using var context = CreateDbContext();
        var expiredEntry = await context.JtiReplayCache.FindAsync(expiredJti);
        var futureEntry = await context.JtiReplayCache.FindAsync(futureJti);
        
        expiredEntry.Should().BeNull("Expired entry should be deleted");
        futureEntry.Should().NotBeNull("Future entry should be retained");
    }

    [Fact]
    public async Task CleanupExpiredAsync_WithNoExpiredEntries_SucceedsGracefully()
    {
        // Arrange
        var sut = new EfJtiReplayCache(
            CreateDbContextFactory(),
            NullLogger<EfJtiReplayCache>.Instance);

        var jti = Guid.NewGuid().ToString();
        await sut.TryMarkUsedAsync(jti, DateTimeOffset.UtcNow.AddMinutes(5));

        // Act
        await sut.CleanupExpiredAsync(); // Should not throw

        // Assert - Entry should still exist
        using var context = CreateDbContext();
        var entry = await context.JtiReplayCache.FindAsync(jti);
        entry.Should().NotBeNull();
    }

    [Fact]
    public async Task TryMarkUsedAsync_MultipleDistinctJtis_AllSucceed()
    {
        // Arrange
        var sut = new EfJtiReplayCache(
            CreateDbContextFactory(),
            NullLogger<EfJtiReplayCache>.Instance);

        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);
        var jti1 = Guid.NewGuid().ToString();
        var jti2 = Guid.NewGuid().ToString();

        // Act
        var result1 = await sut.TryMarkUsedAsync(jti1, expiresAt);
        var result2 = await sut.TryMarkUsedAsync(jti2, expiresAt);

        // Assert
        result1.Should().BeTrue();
        result2.Should().BeTrue();
    }

    private IDbContextFactory<SentinelSecurityDbContext> CreateDbContextFactory()
    {
        // Create a factory that returns a new context each time
        return new DefaultDbContextFactory(_dbOptions);
    }

    private sealed class DefaultDbContextFactory : IDbContextFactory<SentinelSecurityDbContext>
    {
        private readonly DbContextOptions<SentinelSecurityDbContext> _options;

        public DefaultDbContextFactory(DbContextOptions<SentinelSecurityDbContext> options)
        {
            _options = options;
        }

        public SentinelSecurityDbContext CreateDbContext()
        {
            return new SentinelSecurityDbContext(_options);
        }
    }
}
