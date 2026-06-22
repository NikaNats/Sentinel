using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sentinel.AspNetCore.Stores;
using Sentinel.Redis;
using Sentinel.Security.Abstractions.Idempotency;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;

namespace Sentinel.AspNetCore.Infrastructure;

/// <summary>
///     Validates security-critical DI container invariants at application startup.
///     Blocks non-development environments (Staging, UAT, Production) when unsafe configurations
///     such as InMemory stores or RDBMS-backed caches are detected, enforcing a secure-by-default
///     posture and preventing production configuration drift.
/// </summary>
internal sealed class SecurityInvariantsStartupFilter(IServiceProvider serviceProvider, IWebHostEnvironment env)
    : IStartupFilter
{
    private readonly IWebHostEnvironment _env = env ?? throw new ArgumentNullException(nameof(env));

    private readonly ILogger<SecurityInvariantsStartupFilter>? _logger =
        serviceProvider.GetService<ILogger<SecurityInvariantsStartupFilter>>();

    private readonly IServiceProvider _serviceProvider =
        serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        ArgumentNullException.ThrowIfNull(next);

        if (!_env.IsDevelopment())
        {
            _logger?.LogInformation(
                "SecurityInvariantsStartupFilter: Enforcing strict production-grade security invariants in environment: {Env}",
                _env.EnvironmentName);

            var redisOptions = _serviceProvider.GetService<RedisOptions>();
            var redisValidator = _serviceProvider.GetService<IValidateOptions<RedisOptions>>();

            if (redisOptions is not null && redisValidator is not null)
            {
                var validationResult = redisValidator.Validate(null, redisOptions);
                if (validationResult.Failed)
                {
                    _logger?.LogCritical("CRITICAL CONFIGURATION ERROR: Redis options validation failed: {Error}",
                        validationResult.FailureMessage);
                    throw new InvalidOperationException(
                        $"Redis configuration invalid: {validationResult.FailureMessage}");
                }
            }

            var idempotencyStore = _serviceProvider.GetService<IIdempotencyStore>();
            if (idempotencyStore is null or InMemoryIdempotencyStore)
            {
                const string errorMsg =
                    "CRITICAL SECURITY INVARIANT VIOLATED: An insecure InMemoryIdempotencyStore is registered in a non-development environment. " +
                    "Staging, UAT, and Production environments MUST use a distributed, transaction-safe database provider (Redis) to prevent Split-Brain / Double-Spending.";
                _logger?.LogCritical(errorMsg);
                throw new InvalidOperationException(errorMsg);
            }

            var nonceStore = _serviceProvider.GetService<IDpopNonceStore>();
            var jtiCache = _serviceProvider.GetService<IJtiReplayCache>();

            if (nonceStore != null && nonceStore.GetType().Name.StartsWith("Ef", StringComparison.OrdinalIgnoreCase))
            {
                const string errorMsg =
                    "CRITICAL SECURITY INVARIANT VIOLATED: Using EF Core (RDBMS) for DPoP Nonce Store in a non-development environment is forbidden. " +
                    "High-frequency single-use nonces cause fatal database disk I/O bottlenecks and index bloat. Use RedisDpopNonceStore.";
                _logger?.LogCritical(errorMsg);
                throw new InvalidOperationException(errorMsg);
            }

            if (jtiCache != null && jtiCache.GetType().Name.StartsWith("Ef", StringComparison.OrdinalIgnoreCase))
            {
                const string errorMsg =
                    "CRITICAL SECURITY INVARIANT VIOLATED: Using EF Core (RDBMS) for JTI Replay Cache in a non-development environment is forbidden. " +
                    "High-frequency token replay checks must use Redis to prevent database locks and latency spikes.";
                _logger?.LogCritical(errorMsg);
                throw new InvalidOperationException(errorMsg);
            }
        }

        return next;
    }
}
