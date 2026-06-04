using Microsoft.Extensions.Options;

namespace Sentinel.Redis.Validators;

/// <summary>
///     Startup validator for strict Redis-backed security cache configuration.
/// </summary>
internal sealed class RedisOptionsValidator : IValidateOptions<RedisOptions>
{
    public ValidateOptionsResult Validate(string? name, RedisOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.EndPoint))
        {
            return ValidateOptionsResult.Fail("Redis Connection EndPoint must be configured.");
        }

        if (!IsSecureEndpointValue(options.EndPoint))
        {
            return ValidateOptionsResult.Fail("Redis Connection EndPoint contains an invalid or unsafe value.");
        }

        if (options.SyncTimeout <= 0)
        {
            return ValidateOptionsResult.Fail("Redis SyncTimeout must be greater than zero.");
        }

        if (string.IsNullOrWhiteSpace(options.KeyPrefix))
        {
            return ValidateOptionsResult.Fail("Redis KeyPrefix must be configured.");
        }

        return ValidateOptionsResult.Success;
    }

    private static bool IsSecureEndpointValue(string endpoint)
    {
        if (endpoint.Contains("://", StringComparison.Ordinal))
        {
            return false;
        }

        for (var i = 0; i < endpoint.Length; i++)
        {
            var value = endpoint[i];
            if (char.IsControl(value) || char.IsWhiteSpace(value) || value == '*')
            {
                return false;
            }
        }

        return true;
    }
}
