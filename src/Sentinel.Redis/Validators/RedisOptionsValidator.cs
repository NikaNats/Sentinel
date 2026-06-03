using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Sentinel.Redis.Validators;

/// <summary>
///     Production-grade startup validator for Redis options.
///     Blocks application startup if dangerous in-memory fallback is enabled in production.
/// </summary>
internal sealed class RedisOptionsValidator : IValidateOptions<RedisOptions>
{
    private readonly IHostEnvironment _env;

    public RedisOptionsValidator(IHostEnvironment env)
    {
        _env = env ?? throw new ArgumentNullException(nameof(env));
    }

    public ValidateOptionsResult Validate(string? name, RedisOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Critical security barrier: fallback is strictly prohibited in production
        if (_env.IsProduction() && options.EnableInMemoryFallback)
        {
            return ValidateOptionsResult.Fail(
                "CRITICAL SECURITY VIOLATION: 'EnableInMemoryFallback' is enabled in the PRODUCTION environment. " +
                "This allows Split-Brain / Double-Spending vulnerabilities by falling back to local pod memory " +
                "when the Redis cluster is degraded. Production systems must run in Fail-Closed mode. " +
                "Set 'Sentinel:Redis:EnableInMemoryFallback' to 'false' in production appsettings.json.");
        }

        if (string.IsNullOrWhiteSpace(options.EndPoint))
        {
            return ValidateOptionsResult.Fail("Redis Connection EndPoint must be configured.");
        }

        return ValidateOptionsResult.Success;
    }
}
