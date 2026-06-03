using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sentinel.AspNetCore.Stores;
using Sentinel.Redis;
using Sentinel.Security.Abstractions.Idempotency;

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
            // Force Redis options validation at startup
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

            // Block in-memory idempotency store in production
            var idempotencyStore = serviceProvider.GetService<IIdempotencyStore>();

            if (idempotencyStore is null or InMemoryIdempotencyStore)
            {
                throw new InvalidOperationException(
                    "CRITICAL SECURITY INVARIANT VIOLATED: An insecure InMemoryIdempotencyStore is registered in the PRODUCTION environment. " +
                    "Production environments must use a distributed, transaction-safe database provider (Redis) to prevent Split-Brain / Double-Spending.");
            }
        }

        return next;
    }
}
