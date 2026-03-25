using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.StackExchangeRedis;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Sentinel.Redis.Extensions;
using StackExchange.Redis;
using Testcontainers.Keycloak;
using Testcontainers.Redis;

namespace Sentinel.Tests.Shared.Fixtures;

public sealed class RealKeycloakApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    public const string RealmName = "sentinel-test";
    public const string ClientId = "sentinel-api";
    public const string ClientSecret = "sentinel-test-secret";

    private const string AdminUsername = "admin";
    private const string AdminPassword = "admin";
    private readonly KeycloakContainer keycloakContainer;

    private readonly RedisContainer redisContainer;
    private string redisConnectionString = string.Empty;

    public RealKeycloakApiFactory()
    {
        redisContainer = new RedisBuilder("redis:7.4-alpine")
            .WithPortBinding(6379, true)
            .Build();
        keycloakContainer = new KeycloakBuilder("quay.io/keycloak/keycloak:26.1")
            .WithUsername(AdminUsername)
            .WithPassword(AdminPassword)
            .Build();
    }

    public string Authority
    {
        get
        {
            var baseAddress = keycloakContainer.GetBaseAddress().TrimEnd('/');
            return $"{baseAddress}/realms/{RealmName}";
        }
    }

    public string TokenEndpoint => $"{Authority}/protocol/openid-connect/token";

    public async ValueTask InitializeAsync()
    {
        await redisContainer.StartAsync();
        var redisHostPort = redisContainer.GetMappedPublicPort(6379);
        redisConnectionString =
            $"localhost:{redisHostPort},abortConnect=false,connectRetry=5,connectTimeout=5000,syncTimeout=5000";
        await WaitForRedisReadinessAsync("127.0.0.1", redisHostPort, TimeSpan.FromSeconds(30));
        await keycloakContainer.StartAsync();
        var masterAuthority = $"{keycloakContainer.GetBaseAddress().TrimEnd('/')}/realms/master";
        await WaitForDiscoveryDocumentAsync(masterAuthority);
        await EnsureRealmProvisionedAsync();
        await WaitForDiscoveryDocumentAsync(Authority);
        _ = CreateClient();
    }

    ValueTask IAsyncDisposable.DisposeAsync() => new(DisposeAsyncCore());

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            var testSettings = new Dictionary<string, string?>
            {
                ["Keycloak:Authority"] = Authority,
                ["Keycloak:Audience"] = ClientId,
                ["Keycloak:RequireHttpsMetadata"] = "false",
                ["Sentinel:Redis:EndPoint"] = redisConnectionString,
                ["Sentinel:Redis:EnableInMemoryFallback"] = "true",
                ["FeatureFlags:Auth:DpopFlow"] = "true"
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
            services.RemoveAll<IDistributedCache>();
            services.RemoveAll<IConnectionMultiplexer>();
            services.RemoveAll<Sentinel.Security.Abstractions.Replay.IJtiReplayCache>();
            services.RemoveAll<Sentinel.Security.Abstractions.Nonce.IDpopNonceStore>();
            services.RemoveAll<Sentinel.Security.Abstractions.Session.ISessionBlacklistCache>();
            services.RemoveAll<Sentinel.Redis.RedisOptions>();

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
            services.AddSingleton<Sentinel.Application.Common.Abstractions.IJtiReplayCache>(sp =>
                new JtiReplayCacheAdapter(
                    sp.GetRequiredService<Sentinel.Security.Abstractions.Replay.IJtiReplayCache>(),
                    sp.GetService<TimeProvider>()));

            // Bridge Application layer ISessionBlacklistCache to Security layer implementation via adapter
            services.AddSingleton<Sentinel.Application.Common.Abstractions.ISessionBlacklistCache>(sp =>
                new SessionBlacklistCacheAdapter(
                    sp.GetRequiredService<Sentinel.Security.Abstractions.Session.ISessionBlacklistCache>(),
                    sp.GetService<TimeProvider>()));

            // Bridge Application layer IDpopNonceStore to Security layer implementation via adapter
            services.AddSingleton<Sentinel.Application.Common.Abstractions.IDpopNonceStore>(sp =>
                new DpopNonceStoreAdapter(
                    sp.GetRequiredService<Sentinel.Security.Abstractions.Nonce.IDpopNonceStore>()));
        });
    }

    private async Task DisposeAsyncCore()
    {
        await keycloakContainer.DisposeAsync();
        await redisContainer.DisposeAsync();
        await base.DisposeAsync();
    }

    private static async Task WaitForDiscoveryDocumentAsync(string authority)
    {
        using var http = new HttpClient();
        var metadataEndpoint = $"{authority}/.well-known/openid-configuration";

        for (var attempt = 0; attempt < 20; attempt++)
        {
            try
            {
                using var response = await http.GetAsync(metadataEndpoint);
                if (response.IsSuccessStatusCode)
                {
                    return;
                }
            }
#pragma warning disable CA1031
            catch
            {
                // Ignore transient startup failures while Keycloak boots.
            }
#pragma warning restore CA1031

            await Task.Delay(TimeSpan.FromSeconds(1));
        }

        throw new InvalidOperationException($"Keycloak discovery endpoint did not become ready: {metadataEndpoint}");
    }

    private async Task EnsureRealmProvisionedAsync()
    {
        using var http = new HttpClient();
        var adminToken = await GetAdminAccessTokenAsync(http);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        var realmResponse = await http.GetAsync($"{keycloakContainer.GetBaseAddress()}admin/realms/{RealmName}");
        if (realmResponse.IsSuccessStatusCode)
        {
            return;
        }

        var createRealm = await http.PostAsJsonAsync($"{keycloakContainer.GetBaseAddress()}admin/realms", new
        {
            realm = RealmName,
            enabled = true,
            sslRequired = "none"
        });
        createRealm.EnsureSuccessStatusCode();

        var createClient = await http.PostAsJsonAsync(
            $"{keycloakContainer.GetBaseAddress()}admin/realms/{RealmName}/clients", new
            {
                clientId = ClientId,
                protocol = "openid-connect",
                publicClient = false,
                secret = ClientSecret,
                directAccessGrantsEnabled = false,
                standardFlowEnabled = false,
                serviceAccountsEnabled = true,
                attributes = new Dictionary<string, string>
                {
                    ["dpop.bound.access.tokens"] = "true",
                    ["access.token.signed.response.alg"] = "ES256"
                },
                protocolMappers = new object[]
                {
                    new
                    {
                        name = "acr-hardcoded",
                        protocol = "openid-connect",
                        protocolMapper = "oidc-hardcoded-claim-mapper",
                        consentRequired = false,
                        config = new Dictionary<string, string>
                        {
                            ["access.token.claim"] = "true",
                            ["id.token.claim"] = "false",
                            ["claim.name"] = "acr",
                            ["claim.value"] = "acr3",
                            ["jsonType.label"] = "String"
                        }
                    },
                    new
                    {
                        name = "profile-scope-hardcoded",
                        protocol = "openid-connect",
                        protocolMapper = "oidc-hardcoded-claim-mapper",
                        consentRequired = false,
                        config = new Dictionary<string, string>
                        {
                            ["access.token.claim"] = "true",
                            ["id.token.claim"] = "false",
                            ["claim.name"] = "scope",
                            ["claim.value"] = "profile",
                            ["jsonType.label"] = "String"
                        }
                    }
                }
            });
        createClient.EnsureSuccessStatusCode();
    }

    private async Task<string> GetAdminAccessTokenAsync(HttpClient http)
    {
        var tokenEndpoint = $"{keycloakContainer.GetBaseAddress()}realms/master/protocol/openid-connect/token";
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("grant_type", "password"),
                new KeyValuePair<string, string>("client_id", "admin-cli"),
                new KeyValuePair<string, string>("username", AdminUsername),
                new KeyValuePair<string, string>("password", AdminPassword)
            ])
        };

        using var response = await http.SendAsync(request);
        response.EnsureSuccessStatusCode();

        using var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var token = payload.RootElement.GetProperty("access_token").GetString();
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new InvalidOperationException("Unable to acquire Keycloak admin token for integration setup.");
        }

        return token;
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
