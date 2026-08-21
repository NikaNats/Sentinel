using System.Collections.Concurrent;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.EntityFrameworkCore;
using Sentinel.EntityFrameworkCore.Extensions;
using Sentinel.EntityFrameworkCore.Stores;
using Sentinel.Security.Abstractions.Session;

namespace Sentinel.Tests.Unit.Unit;

/// <summary>
///     Composition-root contract tests for AddHybridSessionBlacklistCache:
///     decorator replacement over the L2 binding, and eager fail-fast guards
///     for every missing/misconfigured prerequisite.
/// </summary>
public sealed class HybridSessionBlacklistWiringTests
{
    [Fact(DisplayName =
        "✅ Wiring: hybrid replaces the L2 binding as ISessionBlacklistCache and delegates lookups to it")]
    public async Task AddHybrid_WithValidPrerequisites_ReplacesL2Binding_AsDecorator()
    {
        var services = new ServiceCollection();
        var l2 = new FakeL2Cache();
        services.AddSingleton<ISessionBlacklistCache>(l2);
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton(CreateDbContextFactoryMock().Object);
        services.AddLogging();

        services.AddHybridSessionBlacklistCache(options => options.PubSubChannelPrefix = "test:");

        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<HybridSessionBlacklistCache>().Should().NotBeNull();
        provider.GetRequiredService<ISessionBlacklistCache>().Should().BeOfType<HybridSessionBlacklistCache>(
            "the hybrid must become the effective ISessionBlacklistCache binding");

        // L2-hit path: delegation must reach the wrapped adapter without touching PostgreSQL.
        var hybrid = (HybridSessionBlacklistCache)provider.GetRequiredService<ISessionBlacklistCache>();
        var lookup = await hybrid.IsBlacklistedAsync("session-x");
        lookup.Should().BeTrue();
        l2.QueryCount.Should().Be(1, "lookups must delegate to the wrapped L2 adapter");
    }

    [Fact(DisplayName = "🛡️ Fail-Fast: no registered L2 adapter aborts startup with actionable guidance")]
    public void AddHybrid_WithoutL2Adapter_ThrowsWithGuidance()
    {
        var services = new ServiceCollection();

        var act = () => services.AddHybridSessionBlacklistCache();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*AddRedisSecurityCaches*");
    }

    [Fact(DisplayName = "🛡️ Fail-Fast: scoped L2 adapter is rejected as a captive-dependency hazard")]
    public void AddHybrid_WithScopedL2Adapter_ThrowsCaptiveDependency()
    {
        var services = new ServiceCollection();
        services.AddScoped<ISessionBlacklistCache, FakeL2Cache>();

        var act = () => services.AddHybridSessionBlacklistCache();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Singleton*captive dependency*Scoped*");
    }

    [Fact(DisplayName = "🛡️ Fail-Fast: missing SentinelSecurityDbContext factory aborts startup eagerly")]
    public void AddHybrid_WithoutDbContextFactory_ThrowsEagerly()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ISessionBlacklistCache>(new FakeL2Cache());
        services.AddSingleton(TimeProvider.System);

        var act = () => services.AddHybridSessionBlacklistCache();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IDbContextFactory`1*");
    }

    [Fact(DisplayName = "🛡️ Fail-Fast: missing TimeProvider aborts startup eagerly")]
    public void AddHybrid_WithoutTimeProvider_ThrowsEagerly()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ISessionBlacklistCache>(new FakeL2Cache());
        services.AddSingleton(CreateDbContextFactoryMock().Object);

        var act = () => services.AddHybridSessionBlacklistCache();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*TimeProvider*");
    }

    private static Mock<IDbContextFactory<SentinelSecurityDbContext>> CreateDbContextFactoryMock()
    {
        // Never invoked on the L2-hit path exercised by these tests.
        return new Mock<IDbContextFactory<SentinelSecurityDbContext>>(MockBehavior.Loose);
    }

    private sealed class FakeL2Cache : ISessionBlacklistCache
    {
        private readonly ConcurrentDictionary<string, DateTimeOffset> _blacklisted = new();
        private int _queryCount;

        public int QueryCount => _queryCount;

        public Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default)
        {
            _blacklisted[sessionId] = expiresAt;
            return Task.CompletedTask;
        }

        public Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default)
        {
            // Always report a hit: this keeps the hybrid on the L2 fast path so the
            // (mocked) PostgreSQL factory is never touched during wiring tests.
            Interlocked.Increment(ref _queryCount);
            return Task.FromResult(true);
        }

        public Task CleanupExpiredAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
