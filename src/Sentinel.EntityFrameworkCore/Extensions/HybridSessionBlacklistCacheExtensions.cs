using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sentinel.EntityFrameworkCore.Stores;
using Sentinel.Security.Abstractions.Session;
using StackExchange.Redis;

namespace Sentinel.EntityFrameworkCore.Extensions;

/// <summary>
///     Configuration for the hybrid session blacklist decorator.
/// </summary>
public sealed class HybridSessionBlacklistCacheOptions
{
    /// <summary>
    ///     Prefix for the distributed L1 revocation Pub/Sub channel. Pass the environment's
    ///     Redis <c>KeyPrefix</c> (e.g. "staging:") so distinct environments sharing one Redis
    ///     cluster never cross-pollute each other's local revocation caches.
    /// </summary>
    public string PubSubChannelPrefix { get; set; } = "sentinel:";
}

/// <summary>
///     Composition-root wiring for <see cref="HybridSessionBlacklistCache" />.
///     Decorates an already-registered L2 <see cref="ISessionBlacklistCache" /> adapter
///     (e.g. Redis) with PostgreSQL persistence (source of truth) and a local L1
///     revocation cache, replacing the L2 registration as the effective port binding.
/// </summary>
public static class HybridSessionBlacklistCacheExtensions
{
    /// <summary>
    ///     Wraps the previously registered singleton L2 <see cref="ISessionBlacklistCache" />
    ///     adapter in a <see cref="HybridSessionBlacklistCache" /> (PostgreSQL write-through +
    ///     L1 revocation fast-fail + proactive Pub/Sub invalidation).
    /// </summary>
    /// <remarks>
    ///     Registration order contract:
    ///     1. L2 adapter - <c>services.AddRedisSecurityCaches(...)</c> or any other singleton
    ///        <c>ISessionBlacklistCache</c> registration;
    ///     2. <c>IDbContextFactory&lt;SentinelSecurityDbContext&gt;</c> - e.g.
    ///        <c>services.AddDbContextFactory&lt;SentinelSecurityDbContext&gt;(o =&gt; o.UseNpgsql(cs));</c>;
    ///     3. <c>TimeProvider</c> - usually provided by the Sentinel ASP.NET Core module;
    ///     4. this method last.
    ///     All prerequisites are validated eagerly (fail-fast at startup, not on first request).
    /// </remarks>
    public static IServiceCollection AddHybridSessionBlacklistCache(
        this IServiceCollection services,
        Action<HybridSessionBlacklistCacheOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        // FAIL-FAST: the decorator requires an existing L2 adapter binding to wrap.
        var l2Descriptor = services.LastOrDefault(d => d.ServiceType == typeof(ISessionBlacklistCache))
            ?? throw new InvalidOperationException(
                "AddHybridSessionBlacklistCache requires an L2 ISessionBlacklistCache adapter to wrap. " +
                "Register one first, e.g. services.AddRedisSecurityCaches(...).");

        // FAIL-FAST: a non-singleton L2 inside a singleton decorator is a classic captive-dependency leak.
        if (l2Descriptor.Lifetime != ServiceLifetime.Singleton)
        {
            throw new InvalidOperationException(
                $"The L2 ISessionBlacklistCache registration must be Singleton to avoid a captive dependency " +
                $"inside the singleton HybridSessionBlacklistCache (found {l2Descriptor.Lifetime}).");
        }

        // FAIL-FAST: required co-dependencies.
        RequireService<IDbContextFactory<global::Sentinel.EntityFrameworkCore.SentinelSecurityDbContext>>(services,
            "register it via AddDbContextFactory<SentinelSecurityDbContext>(o => o.UseNpgsql(connectionString))");
        RequireService<TimeProvider>(services,
            "register it via services.AddSingleton(TimeProvider.System)");

        services.AddOptions<HybridSessionBlacklistCacheOptions>()
            .Configure(o => configureOptions?.Invoke(o));

        // Local L1 cache: shared per process; hosts may pre-register their own bounded IMemoryCache.
        services.TryAddSingleton<IMemoryCache, MemoryCache>();

        services.AddSingleton(sp =>
        {
            var l2 = (ISessionBlacklistCache)(
                l2Descriptor.ImplementationInstance
                ?? l2Descriptor.ImplementationFactory?.Invoke(sp)
                ?? ActivatorUtilities.CreateInstance(sp, l2Descriptor.ImplementationType!));

            var options = sp.GetRequiredService<IOptions<HybridSessionBlacklistCacheOptions>>().Value;

            return new HybridSessionBlacklistCache(
                l2,
                sp.GetRequiredService<ILogger<HybridSessionBlacklistCache>>(),
                sp.GetRequiredService<IDbContextFactory<global::Sentinel.EntityFrameworkCore.SentinelSecurityDbContext>>(),
                sp.GetRequiredService<TimeProvider>(),
                options.PubSubChannelPrefix,
                memoryCache: sp.GetService<IMemoryCache>() as MemoryCache,
                memoryCacheOptions: sp.GetService<IOptions<MemoryCacheOptions>>(),
                redisMultiplexer: sp.GetService<IConnectionMultiplexer>());
        });

        services.Replace(ServiceDescriptor.Singleton<ISessionBlacklistCache>(
            sp => sp.GetRequiredService<HybridSessionBlacklistCache>()));

        return services;
    }

    private static void RequireService<TService>(IServiceCollection services, string remediation)
        where TService : class
    {
        if (!services.Any(d => d.ServiceType == typeof(TService)))
        {
            throw new InvalidOperationException(
                $"AddHybridSessionBlacklistCache requires {typeof(TService).Name} to be registered - {remediation}.");
        }
    }
}
