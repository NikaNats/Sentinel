using System.Security.Authentication;
using StackExchange.Redis;

namespace Sentinel.Infrastructure.Cache;

public static class RedisConnectionFactory
{
    public static ConfigurationOptions BuildOptions(RedisOptions options, string? fallbackConnectionString = null)
    {
        var config = new ConfigurationOptions
        {
            User = string.IsNullOrWhiteSpace(options.UserName) ? null : options.UserName,
            Password = string.IsNullOrWhiteSpace(options.Password) ? null : options.Password,
            Ssl = options.UseSsl,
            AllowAdmin = options.AllowAdmin,
            ConnectTimeout = options.ConnectTimeout <= 0 ? 5000 : options.ConnectTimeout,
            AbortOnConnectFail = false,
            ConnectRetry = 3,
            SslProtocols = SslProtocols.Tls13
        };

        foreach (var endpoint in options.EndPoints.Where(static endpoint => !string.IsNullOrWhiteSpace(endpoint)))
        {
            config.EndPoints.Add(endpoint);
        }

        if (config.EndPoints.Count == 0 && !string.IsNullOrWhiteSpace(fallbackConnectionString))
        {
            var fallback = ConfigurationOptions.Parse(fallbackConnectionString);
            foreach (var endpoint in fallback.EndPoints)
            {
                config.EndPoints.Add(endpoint);
            }

            if (string.IsNullOrWhiteSpace(config.Password) && !string.IsNullOrWhiteSpace(fallback.Password))
            {
                config.Password = fallback.Password;
            }
        }

        if (!string.IsNullOrWhiteSpace(options.ServiceName))
        {
            config.ServiceName = options.ServiceName;
            config.CommandMap = CommandMap.Sentinel;
        }

        return config;
    }
}
