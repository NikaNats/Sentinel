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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using Sentinel.EntityFrameworkCore;
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
using Sentinel.Security.Diagnostics;
using Sentinel.Tests.Shared;
using StackExchange.Redis;
using Testcontainers.PostgreSql;
using Testcontainers.Redis;
using Xunit;
using ISsfEventProcessor = Sentinel.Application.Auth.Interfaces.ISsfEventProcessor;

namespace Sentinel.Tests.Integration.Observability;

#pragma warning disable CA2213

/// <summary>
///     Layer-1 observability contract fixture: boots the full sample API with real
///     Postgres/Redis and captures the Sentinel.Auth.Metrics meter and all structured
///     logs through in-memory OpenTelemetry exporters. Used by ObservabilityContractTests
///     to verify that security events (token replay, DPoP failures) are actually emitted -
///     not merely declared.
/// </summary>
public sealed class ObservabilityContractFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly PostgreSqlContainer postgresContainer;
    private readonly RedisContainer redisContainer;
    private string postgresConnectionString = string.Empty;
    private string redisConnectionString = string.Empty;

    public ICollection<MetricSnapshot> Metrics { get; } = [];

    public ICollection<LogRecord> Logs { get; } = [];

    public ObservabilityContractFactory()
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
        await Task.WhenAll(redisContainer.StartAsync(), postgresContainer.StartAsync());

        var redisHostPort = redisContainer.GetMappedPublicPort(6379);
        redisConnectionString =
            $"localhost:{redisHostPort},abortConnect=false,connectRetry=5,connectTimeout=5000,syncTimeout=5000";
        postgresConnectionString = postgresContainer.GetConnectionString();

        await Task.WhenAll(
            WaitForRedisReadinessAsync("127.0.0.1", redisHostPort, TimeSpan.FromSeconds(30)),
            WaitForPostgresReadinessAsync(postgresConnectionString, TimeSpan.FromSeconds(30)));

        _ = CreateClient();

        using var scope = Services.CreateScope();

        var dbContext = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
        await dbContext.Database.MigrateAsync();

        var securityDbContext = scope.ServiceProvider.GetRequiredService<SentinelSecurityDbContext>();
        await securityDbContext.Database.MigrateAsync();
    }

    public override async ValueTask DisposeAsync()
    {
        await Task.WhenAll(
            redisContainer.DisposeAsync().AsTask(),
            postgresContainer.DisposeAsync().AsTask());
        await base.DisposeAsync();
    }

    /// <summary>
    ///     Forces every in-memory exporter (metrics + logs) to flush so the captured
    ///     collections reflect everything emitted up to this point.
    /// </summary>
    public void FlushTelemetryAsync()
    {
        // Metrics: the InMemory metric reader aggregates on its own 60s cycle, so an explicit
        // flush is required to observe measurements. Logs: the InMemory log exporter delivers
        // synchronously at Log() time, so no flush is needed (or available) for log records.
        foreach (var provider in Services.GetServices<MeterProvider>())
        {
            provider.ForceFlush();
        }
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
                // Access-token jti single-use enforcement: enabled ONLY here so the
                // observability contract can verify the replay SIEM path. All other
                // factories keep the default (disabled) behaviour.
                ["FeatureFlags:Auth:JtiReplayEnforcement"] = "true",
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
            services.AddDbContext<SentinelDbContext>(options =>
            {
                options.UseNpgsql(postgresConnectionString, builder =>
                {
                    builder.MigrationsAssembly(typeof(SentinelDbContext).Assembly.GetName().Name);

                    builder.EnableRetryOnFailure(
                        maxRetryCount: 5,
                        maxRetryDelay: TimeSpan.FromSeconds(10),
                        errorCodesToAdd: null);
                });
            });

            services.RemoveAll<DbContextOptions<SentinelSecurityDbContext>>();
            services.AddDbContextFactory<SentinelSecurityDbContext>(options =>
            {
                options.UseNpgsql(postgresConnectionString, builder =>
                {
                    builder.MigrationsAssembly(typeof(SentinelSecurityDbContext).Assembly.GetName().Name);

                    builder.EnableRetryOnFailure(
                        maxRetryCount: 5,
                        maxRetryDelay: TimeSpan.FromSeconds(10),
                        errorCodesToAdd: null);
                });
            });

            services.RemoveAll<SentinelSecurityDbContext>();
            services.AddScoped<SentinelSecurityDbContext>(sp =>
                sp.GetRequiredService<IDbContextFactory<SentinelSecurityDbContext>>().CreateDbContext());

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

            // The security module defaults to BypassPrivacyPreservingHasher (identity) so local
            // dev avoids Vault. This contract MUST pin the production path: real HMAC-SHA256
            // daily-keyed hashing, so the SIEM logs provably carry no raw identifiers.
            services.RemoveAll<IPrivacyPreservingHasher>();
            services.AddSingleton<IPrivacyKeyManager>(new FixedMasterPepperKeyManager());
            services.AddSingleton<IPrivacyPreservingHasher>(sp =>
                new PrivacyPreservingHasher(
                    sp.GetRequiredService<IPrivacyKeyManager>(),
                    sp.GetService<TimeProvider>()));

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

            services.AddOpenTelemetry()
                .WithMetrics(metrics => metrics
                    .AddMeter(AuthTelemetry.MeterName)
                    .AddInMemoryExporter(Metrics))
                .WithLogging(logging => logging.AddInMemoryExporter(Logs));

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

/// <summary>
///     Isolates the observability contract tests: the static OTel meter is shared process-wide,
///     so the collection runs sequentially and only these tests touch it.
/// </summary>
[CollectionDefinition("Sentinel Observability Contract")]
public sealed class ObservabilityContractCollection : ICollectionFixture<ObservabilityContractFactory>
{
}

/// <summary>
///     Test stand-in for the Vault-backed PrivacyKeyManager: a fixed 32-byte master pepper so
///     the real PrivacyPreservingHasher can run without Vault in the contract fixture.
/// </summary>
internal sealed class FixedMasterPepperKeyManager : IPrivacyKeyManager
{
    private static readonly byte[] MasterPepper =
    [
        0x5E, 0x2A, 0xC1, 0x9B, 0x77, 0x44, 0xD8, 0x13,
        0xA6, 0x0F, 0x3B, 0xE9, 0x81, 0x50, 0xCC, 0x27,
        0x92, 0x4D, 0x1E, 0xB0, 0x63, 0xFA, 0x09, 0x35,
        0xC8, 0x72, 0xE5, 0x14, 0x8D, 0x4A, 0x6F, 0xD1
    ];

    public ReadOnlySpan<byte> GetMasterPepper() => MasterPepper;
}
