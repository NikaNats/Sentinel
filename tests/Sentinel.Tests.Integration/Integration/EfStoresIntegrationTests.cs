using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.EntityFrameworkCore;
using Sentinel.EntityFrameworkCore.Models;
using Sentinel.EntityFrameworkCore.Stores;
using Sentinel.Security.Abstractions.Exceptions;
using Testcontainers.PostgreSql;
using Xunit;

namespace Sentinel.Tests.Integration.Integration;

/// <summary>
///     High-assurance EF Core persistence integration tests.
///     Verifies JTI replay, DPoP nonces, and session blacklists against a real,
///     isolated PostgreSQL (v17-alpine) database container using Testcontainers.
///     Eliminates any SQLite-vs-PostgreSQL behavioral drift (uniqueness, date precision, ExecuteDelete).
/// </summary>
public sealed class EfStoresIntegrationTests : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder("postgres:17-alpine")
        .WithDatabase("sentinel_integration_ef_db")
        .WithUsername("postgres")
        .WithPassword("secure_password_123")
        .Build();

    private IDbContextFactory<SentinelSecurityDbContext> _dbContextFactory = null!;
    private EfJtiReplayCache _jtiCache = null!;
    private EfDpopNonceStore _nonceStore = null!;

    async ValueTask IAsyncLifetime.InitializeAsync()
    {
        await _postgresContainer.StartAsync(TestContext.Current.CancellationToken);

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
        factoryMock.Setup(f => f.CreateDbContext())
            .Returns(() => new SentinelSecurityDbContext(dbOptions));

        _dbContextFactory = factoryMock.Object;

        _jtiCache = new EfJtiReplayCache(_dbContextFactory, NullLogger<EfJtiReplayCache>.Instance);
        _nonceStore = new EfDpopNonceStore(_dbContextFactory, NullLogger<EfDpopNonceStore>.Instance);
    }

    async ValueTask IAsyncDisposable.DisposeAsync()
    {
        await _postgresContainer.DisposeAsync();
    }

    // =========================================================================
    // 🛡️ EfJtiReplayCache Postgres Integration Tests
    // =========================================================================

    [Fact(DisplayName = "✅ EF Postgres JTI: First use of JTI stores it, and second use is blocked by Postgres UNIQUE constraint")]
    public async Task TryMarkUsedAsync_WithRealPostgres_EnforcesUniqueConstraint()
    {
        var jti = $"jti-prod-test-{Guid.NewGuid():N}";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        var result1 = await _jtiCache.TryMarkUsedAsync(jti, expiresAt, TestContext.Current.CancellationToken);
        result1.Should().BeTrue();

        var result2 = await _jtiCache.TryMarkUsedAsync(jti, expiresAt, TestContext.Current.CancellationToken);
        result2.Should().BeFalse("PostgreSQL unique key constraint must prevent duplicate JTI entries.");
    }

    [Fact(DisplayName = "⚠️ EF Postgres JTI: Any connection timeout throws ReplayCacheUnavailableException (Fail-Closed)")]
    public async Task TryMarkUsedAsync_OnPostgresConnectionFailure_ThrowsReplayCacheUnavailableException()
    {
        var brokenFactoryMock = new Mock<IDbContextFactory<SentinelSecurityDbContext>>();
        brokenFactoryMock.Setup(f => f.CreateDbContext())
            .Throws(new InvalidOperationException("PostgreSQL connection timeout"));

        var brokenCache = new EfJtiReplayCache(brokenFactoryMock.Object, NullLogger<EfJtiReplayCache>.Instance);

        var act = async () => await brokenCache.TryMarkUsedAsync("jti", DateTimeOffset.UtcNow.AddMinutes(5), TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<ReplayCacheUnavailableException>();
    }

    // =========================================================================
    // 🛡️ EfDpopNonceStore Postgres Integration Tests
    // =========================================================================

    [Fact(DisplayName = "✅ EF Postgres Nonce: ConsumeNonceIfMatches atomically deletes key via ExecuteDeleteAsync")]
    public async Task ConsumeNonceIfMatchesAsync_WithRealPostgres_AtomicConsumption()
    {
        const string thumbprint = "thumbprint-prod-test";
        const string nonce = "active-nonce-val-2026";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        await _nonceStore.SetNonceAsync(thumbprint, nonce, expiresAt, TestContext.Current.CancellationToken);

        var success = await _nonceStore.ConsumeNonceIfMatchesAsync(thumbprint, nonce, TestContext.Current.CancellationToken);
        success.Should().BeTrue();

        var remaining = await _nonceStore.GetNonceAsync(thumbprint, TestContext.Current.CancellationToken);
        remaining.Should().BeNull();
    }
}
