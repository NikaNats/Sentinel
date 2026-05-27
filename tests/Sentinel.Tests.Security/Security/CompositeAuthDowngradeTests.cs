using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
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
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Session;
using Sentinel.Tests.Shared;
using Sentinel.Tests.Shared.Fixtures;
using StackExchange.Redis;
using Testcontainers.Redis;

namespace Sentinel.Tests.Security;

public sealed class CompositeAuthDowngradeTests : IClassFixture<CompositeAuthDowngradeTests.CompositeAuthFactory>
{
    private readonly HttpClient client;

    public CompositeAuthDowngradeTests(CompositeAuthFactory factory)
    {
        client = factory.CreateClient();
    }

    [Fact]
    public async Task BearerTokenWithoutSdJwtFormat_IsRejectedAsDowngrade()
    {
        var token = TestTokenIssuer.MintAccessToken("fake-jkt");
        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/test/protected");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.SendAsync(request, CancellationToken.None);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("invalid_dpop_proof", response.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task BearerSdJwtPresentation_WithInvalidKeyBinding_IsRejected()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/test/protected");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "issuer~disclosure~forged-kb");

        var response = await client.SendAsync(request, CancellationToken.None);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
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

    public sealed class CompositeAuthFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly RedisContainer redisContainer;
        private string redisConnectionString = string.Empty;

        public CompositeAuthFactory()
        {
            redisContainer = new RedisBuilder("redis:7.4-alpine")
                .WithPortBinding(6379, true)
                .Build();
        }

        public async Task InitializeAsync()
        {
            await redisContainer.StartAsync();
            var redisHostPort = redisContainer.GetMappedPublicPort(6379);
            redisConnectionString =
                $"localhost:{redisHostPort},abortConnect=false,connectRetry=5,connectTimeout=5000,syncTimeout=5000";
            await WaitForRedisReadinessAsync("127.0.0.1", redisHostPort, TimeSpan.FromSeconds(30));
            _ = CreateClient();
        }

        Task IAsyncLifetime.DisposeAsync() => DisposeAsyncCore();

        private async Task DisposeAsyncCore()
        {
            await redisContainer.DisposeAsync();
            await base.DisposeAsync();
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
                    ["Sentinel:Redis:EndPoint"] = redisConnectionString,
                    ["Sentinel:Redis:EnableInMemoryFallback"] = "true",
                    ["SdJwt:Enabled"] = "true",
                    ["SdJwt:RequireKeyBindingNonce"] = "false"
                });
            });

            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IDistributedCache>();
                services.RemoveAll<IConnectionMultiplexer>();
                services.RemoveAll<IConfigurationManager<OpenIdConnectConfiguration>>();
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
                    return ConnectionMultiplexer.Connect(options);
                });

                // 🟢 1. დავარეგისტრიროთ Redis-ის უსაფრთხოების ქეშები
                var redisConfig = new ConfigurationBuilder()
                    .AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["EndPoint"] = redisConnectionString,
                        ["EnableInMemoryFallback"] = "true"
                    })
                    .Build();
                services.AddRedisSecurityCaches(redisConfig);

                // 🟢 2. დავაკავშიროთ (Bridge) Application-ფენის ქეშის ინტერფეისები Security-ფენის იმპლემენტაციებთან
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
    }

    private sealed class TestOpenIdConfigurationManager(SecurityKey signingKey)
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
}
