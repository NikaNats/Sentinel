using System.Net.Sockets;
using System.Text;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using DotNet.Testcontainers.Networks;
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
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Redis;
using Sentinel.Redis.Extensions;
using Sentinel.Security.Abstractions.Idempotency;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Session;
using Sentinel.Tests.Shared;
using StackExchange.Redis;
using Testcontainers.Redis;

namespace Sentinel.Tests.Security.Chaos;

public class ChaosSentinelApiFactory : WebApplicationFactory<Sentinel.Sample.MinimalApi.Program>, IAsyncLifetime
{
    private readonly INetwork _network;
    private readonly RedisContainer _redisContainer;
    private readonly IContainer _toxiproxyContainer;

    public ChaosSentinelApiFactory()
    {
        _network = new NetworkBuilder()
            .WithName($"sentinel-chaos-network-{Guid.NewGuid():N}")
            .Build();

        _redisContainer = new RedisBuilder("redis:7.4-alpine")
            .WithNetwork(_network)
            .WithNetworkAliases("redis-backend")
            .Build();

        _toxiproxyContainer = new ContainerBuilder("ghcr.io/shopify/toxiproxy:2.11.0")
            .WithNetwork(_network)
            .WithPortBinding(8474, true) // Admin API
            .WithPortBinding(8666, true) // Redis Proxy Port
            .Build();
    }

    public string RedisProxyConnectionString { get; private set; } = string.Empty;
    public ToxiproxyDbClient? ChaosClient { get; private set; }

    public async ValueTask InitializeAsync()
    {
        await _network.CreateAsync();
        await Task.WhenAll(_redisContainer.StartAsync(), _toxiproxyContainer.StartAsync());

        var adminHost = _toxiproxyContainer.Hostname;
        var adminPort = _toxiproxyContainer.GetMappedPublicPort(8474);
        var proxyPort = _toxiproxyContainer.GetMappedPublicPort(8666);

        ChaosClient = new ToxiproxyDbClient($"http://{adminHost}:{adminPort}");
        await ChaosClient.CreateRedisProxyAsync();

        RedisProxyConnectionString =
            $"{adminHost}:{proxyPort},abortConnect=false,connectRetry=5,connectTimeout=5000,syncTimeout=5000";

        await WaitForTcpReadinessAsync(adminHost, proxyPort, TimeSpan.FromSeconds(30));
        _ = CreateClient();
    }

    // Overriding WebApplicationFactory's DisposeAsync cleanly satisfies IAsyncLifetime.DisposeAsync
    // while also ensuring the base class host receives proper disposal.
    public override async ValueTask DisposeAsync()
    {
        await DisposeAsyncCore();
        await base.DisposeAsync();
        GC.SuppressFinalize(this);
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
                ["ConnectionStrings:Redis"] = RedisProxyConnectionString,
                ["Sentinel:Redis:EndPoint"] = RedisProxyConnectionString,
                ["Sentinel:Redis:EnableInMemoryFallback"] = "false"
            });
        });

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IDistributedCache>();
            services.RemoveAll<IConnectionMultiplexer>();
            services.RemoveAll<IRedisConnectionProvider>();
            services.RemoveAll<IIdempotencyStore>();
            services.RemoveAll<IConfigurationManager<OpenIdConnectConfiguration>>();
            services.RemoveAll<IJtiReplayCache>();
            services.RemoveAll<IDpopNonceStore>();
            services.RemoveAll<ISessionBlacklistCache>();
            services.RemoveAll<RedisOptions>();

            services.AddSingleton<IDistributedCache>(_ =>
                new RedisCache(Options.Create(new RedisCacheOptions { Configuration = RedisProxyConnectionString })));

            services.AddSingleton<IConnectionMultiplexer>(_ =>
            {
                var options = ConfigurationOptions.Parse(RedisProxyConnectionString);
                options.AbortOnConnectFail = false;
                return ConnectionMultiplexer.Connect(options);
            });

            var redisConfig = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["EndPoint"] = RedisProxyConnectionString,
                    ["EnableInMemoryFallback"] = "false"
                })
                .Build();
            services.AddRedisSecurityCaches(redisConfig);
            services.AddTransient<Sentinel.SdJwt.ISdJwtTokenValidator, TestSdJwtTokenValidator>();
            services.AddSingleton<Sentinel.Security.Abstractions.SSF.ISsfTokenValidator, TestSsfTokenValidator>();
            services.AddScoped<Sentinel.Application.Auth.Interfaces.ISsfEventProcessor, SsfEventProcessorAdapter>();
            services.AddScoped<Sentinel.Security.Abstractions.Security.IAuthRevocationService, AuthRevocationServiceAdapter>();

            services.AddSingleton<Application.Common.Abstractions.IJtiReplayCache>(sp =>
                new JtiReplayCacheAdapter(
                    sp.GetRequiredService<IJtiReplayCache>(),
                    sp.GetService<TimeProvider>()));

            services.AddSingleton<Application.Common.Abstractions.ISessionBlacklistCache>(sp =>
                new SessionBlacklistCacheAdapter(
                    sp.GetRequiredService<ISessionBlacklistCache>(),
                    sp.GetService<TimeProvider>()));

            services.AddSingleton<IConfigurationManager<OpenIdConnectConfiguration>>(_ =>
                new TestOpenIdConfigurationManager(TestTokenIssuer.AuthoritySecurityKey));

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

    private async ValueTask DisposeAsyncCore()
    {
        ChaosClient?.Dispose();
        await _toxiproxyContainer.DisposeAsync();
        await _redisContainer.DisposeAsync();
        await _network.DeleteAsync();
    }

    private static async Task WaitForTcpReadinessAsync(string host, int port, TimeSpan timeout)
    {
        var startedAt = DateTime.UtcNow;
        while (DateTime.UtcNow - startedAt < timeout)
        {
            try
            {
                using var tcpClient = new TcpClient();
                await tcpClient.ConnectAsync(host, port);
                if (tcpClient.Connected)
                {
                    return;
                }
            }
            catch (SocketException)
            {
            }

            await Task.Delay(250);
        }

        throw new TimeoutException($"Toxiproxy proxy did not become ready at {host}:{port}");
    }
}

public sealed class ToxiproxyDbClient : IDisposable
{
    private readonly HttpClient _client;

    public ToxiproxyDbClient(string adminUrl)
    {
        _client = new HttpClient { BaseAddress = new Uri(adminUrl) };
    }

    public void Dispose()
    {
        _client.Dispose();
    }

    public async Task CreateRedisProxyAsync()
    {
        var payload =
            "{\"name\":\"redis-proxy\",\"listen\":\"0.0.0.0:8666\",\"upstream\":\"redis-backend:6379\",\"enabled\":true}";
        using var content = new StringContent(payload, Encoding.UTF8, "application/json");
        using var response = await _client.PostAsync("/proxies", content);
        response.EnsureSuccessStatusCode();
    }

    public async Task AddLatencyAsync(int latencyMs, int jitterMs = 0)
    {
        var payload =
            $"{{\"name\":\"latency-toxic\",\"type\":\"latency\",\"stream\":\"downstream\",\"toxicity\":1.0,\"attributes\":{{\"latency\":{latencyMs},\"jitter\":{jitterMs}}}}}";
        using var content = new StringContent(payload, Encoding.UTF8, "application/json");
        using var response = await _client.PostAsync("/proxies/redis-proxy/toxics", content);
        response.EnsureSuccessStatusCode();
    }

    public async Task AddTimeoutAsync(int timeoutMs)
    {
        var payload =
            $"{{\"name\":\"timeout-toxic\",\"type\":\"timeout\",\"stream\":\"downstream\",\"toxicity\":1.0,\"attributes\":{{\"timeout\":{timeoutMs}}}}}";
        using var content = new StringContent(payload, Encoding.UTF8, "application/json");
        using var response = await _client.PostAsync("/proxies/redis-proxy/toxics", content);
        response.EnsureSuccessStatusCode();
    }

    public async Task AddPacketLossAsync(double toxicityRatio)
    {
        _ = toxicityRatio;
        var payload =
            "{\"name\":\"loss-toxic\",\"type\":\"limit_data\",\"stream\":\"downstream\",\"toxicity\":1.0,\"attributes\":{\"bytes\":256}}";
        using var content = new StringContent(payload, Encoding.UTF8, "application/json");
        using var response = await _client.PostAsync("/proxies/redis-proxy/toxics", content);
        response.EnsureSuccessStatusCode();
    }

    public async Task ResetChaosAsync()
    {
        try
        {
            using var res = await _client.DeleteAsync("/proxies/redis-proxy/toxics/latency-toxic");
        }
        catch (HttpRequestException)
        {
        }

        try
        {
            using var res = await _client.DeleteAsync("/proxies/redis-proxy/toxics/timeout-toxic");
        }
        catch (HttpRequestException)
        {
        }

        try
        {
            using var res = await _client.DeleteAsync("/proxies/redis-proxy/toxics/loss-toxic");
        }
        catch (HttpRequestException)
        {
        }
    }
}

file sealed class TestOpenIdConfigurationManager(SecurityKey signingKey)
    : IConfigurationManager<OpenIdConnectConfiguration>
{
    private readonly OpenIdConnectConfiguration configuration = new()
    {
        Issuer = "https://localhost:8443/realms/sentinel"
    };

    public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
    {
        configuration.SigningKeys.Clear();
        configuration.SigningKeys.Add(signingKey);
        return Task.FromResult(configuration);
    }

    public void RequestRefresh()
    {
    }
}
