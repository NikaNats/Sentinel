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
using Sentinel.SdJwt;
using Sentinel.Security.Abstractions.Idempotency;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Security;
using Sentinel.Security.Abstractions.Session;
using Sentinel.Security.Abstractions.SSF;
using StackExchange.Redis;
using Testcontainers.PostgreSql;
using Testcontainers.Redis;
using Xunit;
using ISsfEventProcessor = Sentinel.Application.Auth.Interfaces.ISsfEventProcessor;

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

    public async ValueTask InitializeAsync()
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
        using var scope = Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
        await dbContext.Database.MigrateAsync();
    }

    public override async ValueTask DisposeAsync()
    {
        await DisposeAsyncCore();
        await base.DisposeAsync();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            var testSettings = new Dictionary<string, string?>
            {
                ["Keycloak:Authority"] = "https://localhost:8443/realms/sentinel",
                ["Keycloak:Audience"] = "sentinel-api",
                ["Keycloak:RequireHttpsMetadata"] = "false",
                ["FeatureFlags:Auth:DpopFlow"] = "true",
                ["Sentinel:Redis:EndPoint"] = $"localhost:{redisContainer.GetMappedPublicPort(6379)},abortConnect=false",
                ["Sentinel:Redis:EnableInMemoryFallback"] = "true",
                ["Sentinel:Security:Captcha:SecretKey"] = "0x4AAAAAAABB-MOCK-SECRET",
                ["Sentinel:Security:Captcha:Enabled"] = "false",
                ["DPoP:AllowedAlgorithms:0"] = "PS256",
                ["DPoP:AllowedAlgorithms:1"] = "ES256",
                ["DPoP:AllowedClockSkewSeconds"] = "10",
                ["DPoP:ProofLifetimeSeconds"] = "120"
            };

            var cryptoConfig = TestCryptographyHelper.GenerateTestCryptographyConfig();
            foreach (var kvp in cryptoConfig)
            {
                testSettings[kvp.Key] = kvp.Value;
            }

            config.AddInMemoryCollection(testSettings);
        });

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<DbContextOptions<SentinelDbContext>>();
            services.AddDbContext<SentinelDbContext>(options => { options.UseNpgsql(postgresConnectionString); });

            services.RemoveAll<IDistributedCache>();
            services.RemoveAll<IConnectionMultiplexer>();
            services.RemoveAll<IRedisConnectionProvider>();
            services.RemoveAll<IIdempotencyStore>();
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

            var redisConfig = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["EndPoint"] = redisConnectionString,
                    ["EnableInMemoryFallback"] = "true"
                })
                .Build();
            services.AddRedisSecurityCaches(redisConfig);
            services.AddTransient<ISdJwtTokenValidator, TestSdJwtTokenValidator>();
            services.AddSingleton<ISsfTokenValidator, TestSsfTokenValidator>();

            // Successfully registers SsfEventProcessorAdapter against Application layer interface
            services.AddScoped<ISsfEventProcessor, SsfEventProcessorAdapter>();
            services.AddScoped<IAuthRevocationService, AuthRevocationServiceAdapter>();

            services.AddSingleton<Application.Common.Abstractions.IJtiReplayCache>(sp =>
                new JtiReplayCacheAdapter(
                    sp.GetRequiredService<IJtiReplayCache>(),
                    sp.GetService<TimeProvider>()));

            services.AddSingleton<Application.Common.Abstractions.ISessionBlacklistCache>(sp =>
                new SessionBlacklistCacheAdapter(
                    sp.GetRequiredService<ISessionBlacklistCache>(),
                    sp.GetService<TimeProvider>()));

            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.TokenValidationParameters.IssuerSigningKey = TestTokenIssuer.AuthoritySecurityKey;
                options.TokenValidationParameters.ValidateIssuerSigningKey = true;
                options.TokenValidationParameters.ValidIssuer = "https://localhost:8443/realms/sentinel";
                options.TokenValidationParameters.ValidAudience = "sentinel-api";
                options.RequireHttpsMetadata = false;
                options.ConfigurationManager = null;

                var originalOnMessageReceived = options.Events.OnMessageReceived;
                options.Events.OnMessageReceived = async context =>
                {
                    if (originalOnMessageReceived != null)
                    {
                        await originalOnMessageReceived(context);
                    }

                    context.Options.TokenValidationParameters.IssuerSigningKey = TestTokenIssuer.AuthoritySecurityKey;
                    context.Options.TokenValidationParameters.ValidateIssuerSigningKey = true;
                    context.Options.TokenValidationParameters.ValidIssuer = "https://localhost:8443/realms/sentinel";
                    context.Options.TokenValidationParameters.ValidAudience = "sentinel-api";
                    context.Options.TokenValidationParameters.ValidateIssuer = true;
                    context.Options.TokenValidationParameters.ValidateAudience = true;
                    context.Options.TokenValidationParameters.ValidateLifetime = true;
                    context.Options.TokenValidationParameters.ClockSkew = TimeSpan.Zero;
                    context.Options.TokenValidationParameters.SignatureValidator = null;
                };
            });
        });
    }

    private async ValueTask DisposeAsyncCore() =>
        await Task.WhenAll(
            redisContainer.DisposeAsync().AsTask(),
            postgresContainer.DisposeAsync().AsTask());

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
