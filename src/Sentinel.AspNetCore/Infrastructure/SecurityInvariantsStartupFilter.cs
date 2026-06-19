using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sentinel.AspNetCore.Stores;
using Sentinel.Redis;
using Sentinel.Security.Abstractions.Idempotency;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;

namespace Sentinel.AspNetCore.Infrastructure;

/// <summary>
///     Validates DI container invariants at startup and blocks the application in production if unsafe configurations are
///     detected.
/// </summary>
internal sealed class SecurityInvariantsStartupFilter(IServiceProvider serviceProvider, IWebHostEnvironment env)
    : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        ArgumentNullException.ThrowIfNull(env);
        ArgumentNullException.ThrowIfNull(serviceProvider);

        if (env.IsProduction())
        {
            // 1. Force Redis options validation at startup (Blocks if EndPoint is missing)
            var redisOptions = serviceProvider.GetService<RedisOptions>();
            var redisValidator = serviceProvider.GetService<IValidateOptions<RedisOptions>>();

            if (redisOptions is not null && redisValidator is not null)
            {
                var validationResult = redisValidator.Validate(null, redisOptions);
                if (validationResult.Failed)
                {
                    throw new InvalidOperationException(validationResult.FailureMessage);
                }
            }

            // 2. Block InMemoryIdempotencyStore in production (Prevents Split-Brain / Double-Spending)
            var idempotencyStore = serviceProvider.GetService<IIdempotencyStore>();
            if (idempotencyStore is null or InMemoryIdempotencyStore)
            {
                throw new InvalidOperationException(
                    "CRITICAL SECURITY INVARIANT VIOLATED: An insecure InMemoryIdempotencyStore is registered in the PRODUCTION environment. " +
                    "Production environments must use a distributed, transaction-safe database provider (Redis) to prevent Split-Brain / Double-Spending.");
            }

            // 3. Block RDBMS (EF Core) for ephemeral security caches (Prevents Database DoS and Vacuum Bloat)
            var nonceStore = serviceProvider.GetService<IDpopNonceStore>();
            var jtiCache = serviceProvider.GetService<IJtiReplayCache>();

            if (nonceStore != null && nonceStore.GetType().Name.StartsWith("Ef", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "CRITICAL SECURITY INVARIANT VIOLATED: Using EF Core (RDBMS) for DPoP Nonce Store in PRODUCTION is forbidden. " +
                    "High-frequency single-use nonces cause fatal database disk I/O bottlenecks and index bloat. Use RedisDpopNonceStore.");
            }

            if (jtiCache != null && jtiCache.GetType().Name.StartsWith("Ef", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "CRITICAL SECURITY INVARIANT VIOLATED: Using EF Core for JTI Replay Cache in PRODUCTION is forbidden. " +
                    "High-frequency token replay checks must use Redis to prevent database locks and latency spikes.");
            }
        }

        return next;
    }
}
