using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.StackExchangeRedis;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using Testcontainers.Redis;
using Xunit;
using System.Net.Sockets;

namespace Sentinel.Tests.Integration.Fixtures;

public sealed class SentinelApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly RedisContainer redisContainer;
    private string redisConnectionString = string.Empty;

    public SentinelApiFactory()
    {
        redisContainer = new RedisBuilder("redis:7.4-alpine")
            .WithPortBinding(6379, true)
            .Build();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Keycloak:Authority"] = "https://localhost:8443/realms/sentinel",
                ["Keycloak:Audience"] = "sentinel-api",
                ["Keycloak:RequireHttpsMetadata"] = "false",
                ["ConnectionStrings:Redis"] = redisConnectionString,
                ["FeatureFlags:Auth:DpopFlow"] = "true"
            });
        });

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IDistributedCache>();
            services.RemoveAll<IConnectionMultiplexer>();

            services.AddSingleton<IDistributedCache>(_ =>
                new RedisCache(Options.Create(new RedisCacheOptions { Configuration = redisConnectionString })));

            services.AddSingleton<IConnectionMultiplexer>(_ =>
            {
                var options = ConfigurationOptions.Parse(redisConnectionString);
                options.AbortOnConnectFail = false;
                options.ConnectRetry = 3;
                return ConnectionMultiplexer.Connect(options);
            });

            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.TokenValidationParameters.IssuerSigningKey = TestTokenIssuer.AuthoritySecurityKey;
                options.TokenValidationParameters.ValidateIssuerSigningKey = true;
                options.TokenValidationParameters.ValidIssuer = "https://localhost:8443/realms/sentinel";
                options.TokenValidationParameters.ValidAudience = "sentinel-api";
                options.RequireHttpsMetadata = false;
                options.ConfigurationManager = null;
            });
        });
    }

    public async ValueTask InitializeAsync()
    {
        await redisContainer.StartAsync();
        var redisHostPort = redisContainer.GetMappedPublicPort(6379);
        redisConnectionString = $"localhost:{redisHostPort},abortConnect=false,connectRetry=5,connectTimeout=5000,syncTimeout=5000";
        await WaitForRedisReadinessAsync("127.0.0.1", redisHostPort, TimeSpan.FromSeconds(30));
        _ = CreateClient();
    }

    ValueTask IAsyncDisposable.DisposeAsync() => new(DisposeAsyncCore());

    private async Task DisposeAsyncCore()
    {
        await redisContainer.DisposeAsync();
        await base.DisposeAsync();
    }

    private static async Task WaitForRedisReadinessAsync(string host, int port, TimeSpan timeout)
    {
        var startedAt = DateTime.UtcNow;
        Exception? lastError = null;

        while (DateTime.UtcNow - startedAt < timeout)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(host, port);
                if (client.Connected)
                {
                    return;
                }
            }
            catch (Exception ex) when (ex is SocketException or InvalidOperationException)
            {
                lastError = ex;
            }

            await Task.Delay(250);
        }

        throw new TimeoutException($"Redis readiness check timed out for {host}:{port}", lastError);
    }
}
