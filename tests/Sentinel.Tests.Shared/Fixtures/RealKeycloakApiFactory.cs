using System.IO;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
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
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Redis;
using Sentinel.Redis.Extensions;
using Sentinel.SdJwt;
using Sentinel.Security.Abstractions.Idempotency;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Security;
using Sentinel.Security.Abstractions.Session;
using Sentinel.Security.Abstractions.SSF;
using Sentinel.Tests.Shared;
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
    private static readonly TimeSpan KeycloakHttpClientTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan KeycloakConnectTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan KeycloakReadinessTimeout = TimeSpan.FromSeconds(90);
    private static readonly TimeSpan RedisReadinessTimeout = TimeSpan.FromSeconds(30);

    private readonly string _keycloakCertDirectory;
    private readonly X509Certificate2 _keycloakCertificate;
    private readonly string _keycloakCertPath;
    private readonly string _keycloakKeyPath;
    private readonly KeycloakContainer _keycloakContainer;
    private readonly RedisContainer _redisContainer;

    private string _keycloakBaseAddress = string.Empty;
    private string _redisConnectionString = string.Empty;

    public RealKeycloakApiFactory()
    {
        _redisContainer = new RedisBuilder("redis:7.4-alpine")
            .WithPortBinding(6379, true)
            .Build();

        _keycloakCertDirectory = Path.Combine(Path.GetTempPath(), $"sentinel-keycloak-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_keycloakCertDirectory);
        (_keycloakCertPath, _keycloakKeyPath, _keycloakCertificate) = GenerateKeycloakCertificate(_keycloakCertDirectory);

        // Prepare single realm import directory
        var realmImportDirectory = Path.Combine(_keycloakCertDirectory, "import");
        Directory.CreateDirectory(realmImportDirectory);

        var repoRoot = Directory.GetCurrentDirectory();
        while (!Directory.Exists(Path.Combine(repoRoot, "infra")) && repoRoot != Directory.GetDirectoryRoot(repoRoot))
        {
            repoRoot = Directory.GetParent(repoRoot)?.FullName ?? repoRoot;
        }
        var sourceRealmJsonPath = Path.Combine(repoRoot, "infra", "keycloak", "realms", "sentinel.json");

        var realmJson = File.ReadAllText(sourceRealmJsonPath);
        var realmNode = JsonNode.Parse(realmJson)!;
        realmNode["realm"] = RealmName;

        // Ensure the test client supports client_credentials with client-secret and PS256 DPoP tokens
        var clientsArray = realmNode["clients"]?.AsArray();
        if (clientsArray != null)
        {
            foreach (var clientNode in clientsArray)
            {
                var id = clientNode?["clientId"]?.ToString();
                if (id is "sentinel-api-client" or ClientId)
                {
                    clientNode!["clientId"] = ClientId;
                    clientNode["clientAuthenticatorType"] = "client-secret";
                    clientNode["secret"] = ClientSecret;
                    clientNode["serviceAccountsEnabled"] = true;
                    clientNode["directAccessGrantsEnabled"] = true;
                    clientNode["publicClient"] = false;
                    if (clientNode["attributes"] is JsonObject attrs)
                    {
                        attrs["dpop.bound.access.tokens"] = "true";
                        attrs["access.token.signed.response.alg"] = "PS256";
                    }
                }
            }
        }

        var importRealmPath = Path.Combine(realmImportDirectory, $"{RealmName}.json");
        File.WriteAllText(importRealmPath, realmNode.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));

        _keycloakContainer = new KeycloakBuilder("quay.io/keycloak/keycloak:26.6.4")
            .WithUsername(AdminUsername)
            .WithPassword(AdminPassword)
            .WithEnvironment("KC_HTTP_ENABLED", "false")
            .WithEnvironment("KC_HTTPS_PORT", KeycloakHttpsPort.ToString())
            .WithEnvironment("KC_HTTPS_PROTOCOLS", "TLSv1.3")
            .WithEnvironment("KC_HTTPS_CERTIFICATE_FILE", KeycloakCertContainerPath)
            .WithEnvironment("KC_HTTPS_CERTIFICATE_KEY_FILE", KeycloakKeyContainerPath)
            .WithEnvironment("KC_FEATURES", "dpop,par")
            .WithCommand("--import-realm") // Pass ONLY --import-realm (KeycloakBuilder sets start-dev automatically)
            .WithBindMount(_keycloakCertPath, KeycloakCertContainerPath)
            .WithBindMount(_keycloakKeyPath, KeycloakKeyContainerPath)
            .WithBindMount(realmImportDirectory, "/opt/keycloak/data/import")
            .WithPortBinding(KeycloakHttpsPort, true)
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilMessageIsLogged(".*Keycloak .* started in .*", wait => wait.WithTimeout(KeycloakReadinessTimeout)))
            .Build();
    }

    public string Authority
    {
        get
        {
            if (string.IsNullOrWhiteSpace(_keycloakBaseAddress))
            {
                throw new InvalidOperationException("Keycloak base address is not available before container startup.");
            }

            return $"{_keycloakBaseAddress}/realms/{RealmName}";
        }
    }

    public string TokenEndpoint => $"{Authority}/protocol/openid-connect/token";

    public string KeycloakHost
    {
        get
        {
            if (string.IsNullOrWhiteSpace(_keycloakBaseAddress))
            {
                throw new InvalidOperationException("Keycloak base address is not available before container startup.");
            }

            return new Uri(_keycloakBaseAddress).Host;
        }
    }

    public int KeycloakHttpsMappedPort
    {
        get
        {
            if (string.IsNullOrWhiteSpace(_keycloakBaseAddress))
            {
                throw new InvalidOperationException("Keycloak base address is not available before container startup.");
            }

            return new Uri(_keycloakBaseAddress).Port;
        }
    }

    public async ValueTask InitializeAsync()
    {
        await _redisContainer.StartAsync();
        var redisHostPort = _redisContainer.GetMappedPublicPort(6379);
        _redisConnectionString =
            $"localhost:{redisHostPort},abortConnect=false,connectRetry=5,connectTimeout=5000,syncTimeout=5000";
        await WaitForRedisReadinessAsync("127.0.0.1", redisHostPort, RedisReadinessTimeout);

        await _keycloakContainer.StartAsync();
        _keycloakBaseAddress = BuildKeycloakBaseAddress();

        var masterAuthority = $"{_keycloakBaseAddress}/realms/master";
        await WaitForDiscoveryDocumentAsync(masterAuthority, KeycloakReadinessTimeout);
        await WaitForDiscoveryDocumentAsync(Authority, KeycloakReadinessTimeout);

        await PreFetchJwksAsync();
    }

    private async Task PreFetchJwksAsync()
    {
        using var httpClient = CreateKeycloakHttpClient();
        var jwksUri = $"{Authority}/protocol/openid-connect/certs";

        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                var response = await httpClient.GetAsync(jwksUri, CancellationToken.None);
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    if (!string.IsNullOrWhiteSpace(content) && content.Contains("\"keys\""))
                    {
                        return;
                    }
                }
            }
            catch
            {
                // Retry on transient network glitches
            }

            await Task.Delay(TimeSpan.FromSeconds(2));
        }

        var finalResponse = await httpClient.GetAsync(jwksUri, CancellationToken.None);
        finalResponse.EnsureSuccessStatusCode();
        var finalContent = await finalResponse.Content.ReadAsStringAsync();
        if (string.IsNullOrWhiteSpace(finalContent) || !finalContent.Contains("\"keys\""))
        {
            throw new InvalidOperationException("Failed to pre-fetch JWKS from Keycloak");
        }
    }

    public override async ValueTask DisposeAsync()
    {
        await _keycloakContainer.DisposeAsync();
        await _redisContainer.DisposeAsync();
        _keycloakCertificate.Dispose();
        await base.DisposeAsync();

        if (Directory.Exists(_keycloakCertDirectory))
        {
            try { Directory.Delete(_keycloakCertDirectory, true); } catch { /* best effort */ }
        }
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
                ["Sentinel:Redis:EndPoint"] = _redisConnectionString,
                ["FeatureFlags:Auth:DpopFlow"] = "true",
                ["Sentinel:Security:Captcha:SecretKey"] = "0x4AAAAAAABB-MOCK-SECRET",
                ["Sentinel:Security:Captcha:Enabled"] = "false"
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
            services.RemoveAll<IDistributedCache>();
            services.RemoveAll<IConnectionMultiplexer>();
            services.RemoveAll<IRedisConnectionProvider>();
            services.RemoveAll<IIdempotencyStore>();
            services.RemoveAll<IJtiReplayCache>();
            services.RemoveAll<IDpopNonceStore>();
            services.RemoveAll<ISessionBlacklistCache>();
            services.RemoveAll<RedisOptions>();

            services.AddSingleton<IDistributedCache>(_ =>
                new RedisCache(Options.Create(new RedisCacheOptions { Configuration = _redisConnectionString })));

            services.AddSingleton<IConnectionMultiplexer>(_ =>
            {
                var options = ConfigurationOptions.Parse(_redisConnectionString);
                options.AbortOnConnectFail = false;
                options.ConnectRetry = 3;
                return ConnectionMultiplexer.Connect(options);
            });

            var redisConfig = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["EndPoint"] = _redisConnectionString
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

            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.RequireHttpsMetadata = true;
                options.Authority = Authority;
                options.MetadataAddress = $"{Authority}/.well-known/openid-configuration";
                options.Backchannel = CreateKeycloakHttpClient();

                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    options.MetadataAddress,
                    new OpenIdConnectConfigurationRetriever(),
                    new HttpDocumentRetriever(options.Backchannel)
                    {
                        RequireHttps = options.RequireHttpsMetadata,
                    });

                options.TokenValidationParameters.IssuerSigningKey = null;
                options.TokenValidationParameters.IssuerSigningKeys = null;
                options.TokenValidationParameters.ValidIssuer = Authority;
                options.TokenValidationParameters.ValidAudience = ClientId;
                options.TokenValidationParameters.ValidateLifetime = true;
                options.TokenValidationParameters.ClockSkew = TimeSpan.Zero;
                options.TokenValidationParameters.RequireSignedTokens = true;
                options.TokenValidationParameters.ValidAlgorithms = ["PS256", "ES256"];
            });
        });
    }

#pragma warning disable CA1822
    public static HttpClient CreateKeycloakHttpClient() => CreateKeycloakHttpClient(SslProtocols.Tls13);

    public static HttpClient CreateKeycloakHttpClient(SslProtocols protocols)
    {
#pragma warning disable CA2000
        var handler = new SocketsHttpHandler
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
        };

        return new HttpClient(handler, true)
        {
            Timeout = KeycloakHttpClientTimeout
        };
#pragma warning restore CA2000
    }
#pragma warning restore CA1822

    public static bool ValidateKeycloakCertificate(object _, X509Certificate? certificate, X509Chain? __, SslPolicyErrors sslPolicyErrors)
    {
        if (certificate is null)
        {
            return false;
        }

        if (certificate is X509Certificate2 cert2)
        {
            var now = DateTime.UtcNow;
            if (cert2.NotAfter < now || cert2.NotBefore > now)
            {
                return false;
            }
        }

        return true;
    }

    public bool IsExpectedKeycloakCertificate(X509Certificate certificate)
    {
        var expectedThumbprint = _keycloakCertificate.GetCertHashString(HashAlgorithmName.SHA256);
        var actualThumbprint = certificate.GetCertHashString(HashAlgorithmName.SHA256);

        return string.Equals(actualThumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase);
    }

    private string BuildKeycloakBaseAddress()
    {
        var baseAddress = new Uri(_keycloakContainer.GetBaseAddress());
        var port = _keycloakContainer.GetMappedPublicPort(KeycloakHttpsPort);
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

    private static async Task WaitForDiscoveryDocumentAsync(string authority, TimeSpan timeout)
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