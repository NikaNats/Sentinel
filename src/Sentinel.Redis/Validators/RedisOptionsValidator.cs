using Microsoft.Extensions.Options;

namespace Sentinel.Redis.Validators;

/// <summary>
///     Startup validator for strict Redis and Redis Sentinel HA security cache configuration.
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

        if (options.ConnectTimeout <= 0)
        {
            return ValidateOptionsResult.Fail("Redis ConnectTimeout must be greater than zero.");
        }

        if (string.IsNullOrWhiteSpace(options.KeyPrefix))
        {
            return ValidateOptionsResult.Fail("Redis KeyPrefix must be configured.");
        }

        // Sentinel HA validation
        if (options.ServiceName is not null)
        {
            if (string.IsNullOrWhiteSpace(options.ServiceName) || !IsSecureServiceName(options.ServiceName))
            {
                return ValidateOptionsResult.Fail("Redis ServiceName (Sentinel Master) contains invalid characters.");
            }
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

    private static bool IsSecureServiceName(string serviceName)
    {
        for (var i = 0; i < serviceName.Length; i++)
        {
            var value = serviceName[i];
            if (char.IsControl(value) || char.IsWhiteSpace(value) || value == '*' || value == ':' || value == ',')
            {
                return false;
            }
        }

        return true;
    }
}