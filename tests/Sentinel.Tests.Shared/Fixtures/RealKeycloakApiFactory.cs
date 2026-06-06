using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using DotNet.Testcontainers.Builders;
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
using Testcontainers.Keycloak;
using Testcontainers.Redis;
using Xunit;
using ISsfEventProcessor = Sentinel.Application.Auth.Interfaces.ISsfEventProcessor;

namespace Sentinel.Tests.Shared.Fixtures;

#pragma warning disable CA2213

public sealed class RealKeycloakApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    public const string RealmName = "sentinel-test";
    public const string ClientId = "sentinel-api";
    public const string ClientSecret = "sentinel-test-secret";

    private const ushort KeycloakHttpsPort = 8443;
    private const string KeycloakCertContainerPath = "/etc/x509/https/tls.crt";
    private const string KeycloakKeyContainerPath = "/etc/x509/https/tls.key";

    private const string AdminUsername = "admin";
    private const string AdminPassword = "admin";
    private static readonly TimeSpan KeycloakHttpClientTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan KeycloakConnectTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan KeycloakReadinessTimeout = TimeSpan.FromSeconds(90);
    private static readonly TimeSpan RedisReadinessTimeout = TimeSpan.FromSeconds(30);
    private readonly string keycloakCertDirectory;
    private readonly X509Certificate2 keycloakCertificate;
    private readonly string keycloakCertPath;
    private readonly KeycloakContainer keycloakContainer;
    private readonly string keycloakKeyPath;

    private readonly RedisContainer redisContainer;
    private string keycloakBaseAddress = string.Empty;
    private string redisConnectionString = string.Empty;

    public RealKeycloakApiFactory()
    {
        redisContainer = new RedisBuilder("redis:7.4-alpine")
            .WithPortBinding(6379, true)
            .Build();
        keycloakCertDirectory = Path.Combine(Path.GetTempPath(), $"sentinel-keycloak-{Guid.NewGuid():N}");
        Directory.CreateDirectory(keycloakCertDirectory);
        (keycloakCertPath, keycloakKeyPath, keycloakCertificate) = GenerateKeycloakCertificate(keycloakCertDirectory);
        keycloakContainer = new KeycloakBuilder("quay.io/keycloak/keycloak:26.1")
            .WithUsername(AdminUsername)
            .WithPassword(AdminPassword)
            .WithEnvironment("KC_HTTP_ENABLED", "false")
            .WithEnvironment("KC_HTTPS_PORT", KeycloakHttpsPort.ToString())
            .WithEnvironment("KC_HTTPS_PROTOCOLS", "TLSv1.3")
            .WithEnvironment("KC_HTTPS_CERTIFICATE_FILE", KeycloakCertContainerPath)
            .WithEnvironment("KC_HTTPS_CERTIFICATE_KEY_FILE", KeycloakKeyContainerPath)
            .WithBindMount(keycloakCertPath, KeycloakCertContainerPath)
            .WithBindMount(keycloakKeyPath, KeycloakKeyContainerPath)
            .WithPortBinding(KeycloakHttpsPort, true)
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilMessageIsLogged("Listening on:", wait => wait.WithTimeout(KeycloakReadinessTimeout)))
            .Build();
    }

    public string Authority
    {
        get
        {
            if (string.IsNullOrWhiteSpace(keycloakBaseAddress))
            {
                throw new InvalidOperationException("Keycloak base address is not available before container startup.");
            }

            return $"{keycloakBaseAddress}/realms/{RealmName}";
        }
    }

    public string TokenEndpoint => $"{Authority}/protocol/openid-connect/token";

    public string KeycloakHost
    {
        get
        {
            if (string.IsNullOrWhiteSpace(keycloakBaseAddress))
            {
                throw new InvalidOperationException("Keycloak base address is not available before container startup.");
            }

            return new Uri(keycloakBaseAddress).Host;
        }
    }

    public int KeycloakHttpsMappedPort
    {
        get
        {
            if (string.IsNullOrWhiteSpace(keycloakBaseAddress))
            {
                throw new InvalidOperationException("Keycloak base address is not available before container startup.");
            }

            return new Uri(keycloakBaseAddress).Port;
        }
    }

    public async ValueTask InitializeAsync()
    {
        await redisContainer.StartAsync();
        var redisHostPort = redisContainer.GetMappedPublicPort(6379);
        redisConnectionString =
            $"localhost:{redisHostPort},abortConnect=false,connectRetry=5,connectTimeout=5000,syncTimeout=5000";
        await WaitForRedisReadinessAsync("127.0.0.1", redisHostPort, RedisReadinessTimeout);
        await keycloakContainer.StartAsync();
        keycloakBaseAddress = BuildKeycloakBaseAddress();
        var masterAuthority = $"{keycloakBaseAddress}/realms/master";
        await WaitForDiscoveryDocumentAsync(masterAuthority, KeycloakReadinessTimeout);
        await EnsureRealmProvisionedAsync();
        await WaitForDiscoveryDocumentAsync(Authority, KeycloakReadinessTimeout);
    }

    // Overriding DisposeAsync instead of shadowing it avoids warnings and ensures base host cleanup.
    public override async ValueTask DisposeAsync()
    {
        await DisposeAsyncCore();
        await base.DisposeAsync();
    }

    private async ValueTask DisposeAsyncCore()
    {
        await keycloakContainer.DisposeAsync();
        await redisContainer.DisposeAsync();
        keycloakCertificate.Dispose();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            var testSettings = new Dictionary<string, string?>
            {
                ["Keycloak:Authority"] = Authority,
                ["Keycloak:Audience"] = ClientId,
                ["Keycloak:RequireHttpsMetadata"] = "true",
                ["Sentinel:Redis:EndPoint"] = redisConnectionString,
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

            // Register Redis security caches using configuration-based approach
            var redisConfig = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["EndPoint"] = redisConnectionString
                })
                .Build();
            services.AddRedisSecurityCaches(redisConfig);
            services.AddTransient<ISdJwtTokenValidator, TestSdJwtTokenValidator>();
            services.AddSingleton<ISsfTokenValidator, TestSsfTokenValidator>();
            services.AddScoped<ISsfEventProcessor, SsfEventProcessorAdapter>();
            services.AddScoped<IAuthRevocationService, AuthRevocationServiceAdapter>();

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

            // Real-Keycloak tests should validate JWTs against live Keycloak signing keys.
            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.RequireHttpsMetadata = true;
                options.Authority = Authority;
                options.MetadataAddress = $"{Authority}/.well-known/openid-configuration";
                options.Backchannel = CreateKeycloakHttpClient();

                options.TokenValidationParameters.IssuerSigningKey = null;
                options.TokenValidationParameters.IssuerSigningKeys = null;
                options.TokenValidationParameters.ValidIssuer = Authority;
                options.TokenValidationParameters.ValidAudience = ClientId;
            });
        });
    }

    public HttpClient CreateKeycloakHttpClient() => CreateKeycloakHttpClient(SslProtocols.Tls13);

    public HttpClient CreateKeycloakHttpClient(SslProtocols protocols)
    {
#pragma warning disable CA2000
        return new HttpClient(
            new SocketsHttpHandler
            {
                ConnectTimeout = KeycloakConnectTimeout,
                PooledConnectionLifetime = TimeSpan.FromMinutes(2),
                PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
                SslOptions = new SslClientAuthenticationOptions
                {
                    EnabledSslProtocols = protocols,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    RemoteCertificateValidationCallback = ValidateKeycloakCertificate
                }
            },
            true)
        {
            Timeout = KeycloakHttpClientTimeout
        };
#pragma warning restore CA2000
    }

    public bool ValidateKeycloakCertificate(object _, X509Certificate? certificate, X509Chain? __,
        SslPolicyErrors ___)
    {
        if (certificate is null)
        {
            return false;
        }

        return IsExpectedKeycloakCertificate(certificate);
    }

    public bool IsExpectedKeycloakCertificate(X509Certificate certificate)
    {
        var expectedThumbprint = keycloakCertificate.GetCertHashString(HashAlgorithmName.SHA256);
        var actualThumbprint = certificate.GetCertHashString(HashAlgorithmName.SHA256);

        return string.Equals(actualThumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase);
    }

    private string BuildKeycloakBaseAddress()
    {
        var baseAddress = new Uri(keycloakContainer.GetBaseAddress());
        var port = keycloakContainer.GetMappedPublicPort(KeycloakHttpsPort);
        return new UriBuilder(Uri.UriSchemeHttps, baseAddress.Host, port).ToString().TrimEnd('/');
    }

    private static (string CertPath, string KeyPath, X509Certificate2 Certificate) GenerateKeycloakCertificate(
        string directory)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=localhost",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddDnsName("keycloak");
        sanBuilder.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(sanBuilder.Build());

        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(5));

        var certPath = Path.Combine(directory, "keycloak.crt");
        var keyPath = Path.Combine(directory, "keycloak.key");

        File.WriteAllText(certPath, certificate.ExportCertificatePem());
        File.WriteAllText(keyPath, rsa.ExportPkcs8PrivateKeyPem());

        var keycloakCertificate = X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
        return (certPath, keyPath, keycloakCertificate);
    }

    private async Task WaitForDiscoveryDocumentAsync(string authority, TimeSpan timeout)
    {
        using var http = CreateKeycloakHttpClient();
        var metadataEndpoint = $"{authority}/.well-known/openid-configuration";
        var startedAt = DateTime.UtcNow;
        Exception? lastError = null;

        while (DateTime.UtcNow - startedAt < timeout)
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
            catch (Exception ex)
            {
                lastError = ex;
            }
#pragma warning restore CA1031

            await Task.Delay(TimeSpan.FromSeconds(1));
        }

        throw new TimeoutException($"Keycloak discovery endpoint did not become ready: {metadataEndpoint}", lastError);
    }

    private async Task EnsureRealmProvisionedAsync()
    {
        using var http = CreateKeycloakHttpClient();
        var adminToken = await GetAdminAccessTokenAsync(http);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        var realmResponse = await http.GetAsync($"{keycloakBaseAddress}/admin/realms/{RealmName}");
        if (realmResponse.IsSuccessStatusCode)
        {
            return;
        }

        var createRealm = await http.PostAsJsonAsync($"{keycloakBaseAddress}/admin/realms", new
        {
            realm = RealmName,
            enabled = true,
            sslRequired = "none"
        });
        createRealm.EnsureSuccessStatusCode();

        var createClient = await http.PostAsJsonAsync(
            $"{keycloakBaseAddress}/admin/realms/{RealmName}/clients", new
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
        var tokenEndpoint = $"{keycloakBaseAddress}/realms/master/protocol/openid-connect/token";
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
