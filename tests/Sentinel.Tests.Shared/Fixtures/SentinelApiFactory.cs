using System.Net.Sockets;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.StackExchangeRedis;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Npgsql;
using Sentinel.Infrastructure.Persistence;
using Sentinel.Redis;
using Sentinel.Redis.Extensions;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Session;
using StackExchange.Redis;
using Testcontainers.PostgreSql;
using Testcontainers.Redis;

namespace Sentinel.Tests.Shared.Fixtures;

#pragma warning disable CA2213

public sealed class SentinelApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly PostgreSqlContainer postgresContainer;
    private readonly RedisContainer redisContainer;
    private string postgresConnectionString = string.Empty;
    private string redisConnectionString = string.Empty;

    public SentinelApiFactory()
    {
        redisContainer = new RedisBuilder("redis:7.4-alpine")
            .WithPortBinding(6379, true)
            .Build();

        postgresContainer = new PostgreSqlBuilder("postgres:16-alpine")
            .WithDatabase("sentinel_test")
            .WithUsername("sentinel")
            .WithPassword("sentinel_password")
            .WithPortBinding(5432, true)
            .Build();
    }

    public async Task InitializeAsync()
    {
        // 1. Start containers in parallel
        await Task.WhenAll(redisContainer.StartAsync(), postgresContainer.StartAsync());

        var redisHostPort = redisContainer.GetMappedPublicPort(6379);
        redisConnectionString =
            $"localhost:{redisHostPort},abortConnect=false,connectRetry=5,connectTimeout=5000,syncTimeout=5000";
        postgresConnectionString = postgresContainer.GetConnectionString();

        // 2. Critical: Wait for BOTH containers to be ready
        await Task.WhenAll(
            WaitForRedisReadinessAsync("127.0.0.1", redisHostPort, TimeSpan.FromSeconds(30)),
            WaitForPostgresReadinessAsync(postgresConnectionString, TimeSpan.FromSeconds(30)));

        // 3. NOW create the client which triggers ConfigureWebHost
        _ = CreateClient();

        // 4. ARCHITECT'S FIX: Run migrations AFTER CreateClient (Services container exists)
        // This happens after the WebHost is built but before tests actually run
        using var scope = Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
        await dbContext.Database.MigrateAsync();
    }

    Task IAsyncLifetime.DisposeAsync() => DisposeAsyncCore();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // ARCHITECT'S 2026 FIX: Direct DI Injection pattern
        // We SKIP builder.UseSetting() for connection strings because it doesn't reach
        // ConfigureTestServices in time. Instead, we inject directly into the DI container.

        builder.ConfigureAppConfiguration((_, config) =>
        {
            // Keep non-connection string configurations here
            var testSettings = new Dictionary<string, string?>
            {
                ["Keycloak:Authority"] = "https://localhost:8443/realms/sentinel",
                ["Keycloak:Audience"] = "sentinel-api",
                ["Keycloak:RequireHttpsMetadata"] = "false",
                ["FeatureFlags:Auth:DpopFlow"] = "true",
                // Add Redis configuration for test containers
                ["Sentinel:Redis:EndPoint"] =
                    $"localhost:{redisContainer.GetMappedPublicPort(6379)},abortConnect=false",
                ["Sentinel:Redis:EnableInMemoryFallback"] = "true"
            };

            // Add test cryptography configuration
            var cryptoConfig = TestCryptographyHelper.GenerateTestCryptographyConfig();
            foreach (var kvp in cryptoConfig)
            {
                testSettings[kvp.Key] = kvp.Value;
            }

            config.AddInMemoryCollection(testSettings);
        });

        builder.ConfigureTestServices(services =>
        {
            // DIRECTLY inject the dynamic connection strings where the container variables are available!

            // Configure DbContext with explicit container connection string
            services.RemoveAll<DbContextOptions<SentinelDbContext>>();
            services.AddDbContext<SentinelDbContext>(options => { options.UseNpgsql(postgresConnectionString); });

            // Configure Redis with explicit container connection string
            services.RemoveAll<IDistributedCache>();
            services.RemoveAll<IConnectionMultiplexer>();
            services.RemoveAll<IJtiReplayCache>();
            services.RemoveAll<IDpopNonceStore>();
            services.RemoveAll<ISessionBlacklistCache>();
            services.RemoveAll<RedisOptions>();

            services.AddSingleton<IDistributedCache>(_ =>
                new RedisCache(Options.Create(new RedisCacheOptions { Configuration = redisConnectionString })));

            services.AddSingleton<IConnectionMultiplexer>(_ =>
            {
                var options = ConfigurationOptions.Parse(redisConnectionString);
                options.AbortOnConnectFail = false;
                options.ConnectRetry = 3;
                return ConnectionMultiplexer.Connect(options);
            });

            // Register Redis security caches using configuration-based approach
            var redisConfig = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["EndPoint"] = redisConnectionString,
                    ["EnableInMemoryFallback"] = "true"
                })
                .Build();
            services.AddRedisSecurityCaches(redisConfig);

            // Bridge Application layer IJtiReplayCache to Security layer implementation via adapter
            services.AddSingleton<Application.Common.Abstractions.IJtiReplayCache>(sp =>
                new JtiReplayCacheAdapter(
                    sp.GetRequiredService<IJtiReplayCache>(),
                    sp.GetService<TimeProvider>()));

            // Bridge Application layer ISessionBlacklistCache to Security layer implementation via adapter
            services.AddSingleton<Application.Common.Abstractions.ISessionBlacklistCache>(sp =>
                new SessionBlacklistCacheAdapter(
                    sp.GetRequiredService<ISessionBlacklistCache>(),
                    sp.GetService<TimeProvider>()));

            // Configure JWT authentication override
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

    private async Task DisposeAsyncCore()
    {
        await Task.WhenAll(
            redisContainer.DisposeAsync().AsTask(),
            postgresContainer.DisposeAsync().AsTask());
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

    private static async Task WaitForPostgresReadinessAsync(string connectionString, TimeSpan timeout)
    {
        var startedAt = DateTime.UtcNow;
        Exception? lastError = null;

        while (DateTime.UtcNow - startedAt < timeout)
        {
            try
            {
                // Attempt to open a connection to verify the database is accepting connections
                using var connection = new NpgsqlConnection(connectionString);
                await connection.OpenAsync();
                await connection.CloseAsync();
                return;
            }
            catch (NpgsqlException ex)
            {
                lastError = ex;
            }
            catch (InvalidOperationException ex)
            {
                lastError = ex;
            }

            await Task.Delay(250);
        }

        throw new TimeoutException("PostgreSQL readiness check timed out", lastError);
    }
}
