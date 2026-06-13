using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
using Microsoft.IdentityModel.JsonWebTokens;
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
using StackExchange.Redis;
using Testcontainers.Redis;
using ISsfEventProcessor = Sentinel.Application.Auth.Interfaces.ISsfEventProcessor;

#pragma warning disable CA2213

namespace Sentinel.Tests.Integration.Integration;

public sealed class SdJwtFlowIntegrationTests(SdJwtFlowIntegrationTests.SdJwtApiFactory factory)
    : IClassFixture<SdJwtFlowIntegrationTests.SdJwtApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Profile_WithSdJwtPresentation_MaterializesOnlyDisclosedClaims()
    {
        using var holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var holderJwk = CreateEcJwkObject(holderKey);
        var holderJkt = ComputeEcThumbprint(holderJwk);

        var disclosedName = CreateDisclosure("salt-1", "name", "Selective User");
        var hiddenEmail = CreateDisclosure("salt-2", "email", "hidden@example.com");
        var issuerJwt = CreateIssuerJwt([ComputeDisclosureDigest(disclosedName)], holderJkt);
        var kbJwt = CreateKeyBindingJwt(holderKey, holderJwk, issuerJwt, [disclosedName, hiddenEmail], "sentinel-api");
        var presentation = $"{issuerJwt}~{disclosedName}~{hiddenEmail}~{kbJwt}";

        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/profile");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", presentation);

        var response = await _client.SendAsync(request, CancellationToken.None);
        var body = await response.Content.ReadAsStringAsync(CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Selective User", body, StringComparison.Ordinal);
        Assert.DoesNotContain("hidden@example.com", body, StringComparison.Ordinal);
    }

    private static string CreateIssuerJwt(string[] disclosureDigests, string holderJkt)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "https://localhost:8443/realms/sentinel",
            Audience = "sentinel-api",
            Claims = new Dictionary<string, object>
            {
                ["sub"] = "sdjwt-user-1",
                ["scope"] = "profile",
                ["acr"] = "acr2",
                ["_sd"] = disclosureDigests,
                ["_sd_alg"] = "sha-256",
                ["cnf"] = new Dictionary<string, string> { ["jkt"] = holderJkt }
            },
            Expires = DateTimeOffset.UtcNow.AddMinutes(5).UtcDateTime,
            SigningCredentials =
                new SigningCredentials(TestTokenIssuer.AuthoritySecurityKey, SecurityAlgorithms.EcdsaSha256)
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static string CreateKeyBindingJwt(ECDsa holderKey, Dictionary<string, string> holderJwk, string issuerJwt,
        string[] disclosures, string audience)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Audience = audience,
            Claims = new Dictionary<string, object>
            {
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["sd_hash"] = ComputeSdHash(issuerJwt, disclosures)
            },
            Expires = DateTimeOffset.UtcNow.AddMinutes(5).UtcDateTime,
            SigningCredentials =
                new SigningCredentials(new ECDsaSecurityKey(holderKey), SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = holderJwk }
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static string CreateDisclosure(string salt, string claimName, string claimValue)
    {
        var json = JsonSerializer.Serialize(new object[] { salt, claimName, claimValue });
        return Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(json));
    }

    private static string ComputeDisclosureDigest(string disclosure) =>
        Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(disclosure)));

    private static string ComputeSdHash(string issuerJwt, string[] disclosures)
    {
        var presentationNoKb = $"{issuerJwt}~{string.Join("~", disclosures)}";
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(presentationNoKb)));
    }

    private static Dictionary<string, string> CreateEcJwkObject(ECDsa holderKey)
    {
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(holderKey));
        return new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };
    }

    private static string ComputeEcThumbprint(Dictionary<string, string> jwkObject)
    {
        var canonical = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["crv"] = jwkObject["crv"],
            ["kty"] = jwkObject["kty"],
            ["x"] = jwkObject["x"],
            ["y"] = jwkObject["y"]
        });

        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
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

    public sealed class SdJwtApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly RedisContainer _redisContainer = new RedisBuilder("redis:7.4-alpine")
            .WithPortBinding(6379, true)
            .Build();

        private string _redisConnectionString = string.Empty;

        public async ValueTask InitializeAsync()
        {
            await _redisContainer.StartAsync();
            var redisHostPort = _redisContainer.GetMappedPublicPort(6379);
            _redisConnectionString =
                $"localhost:{redisHostPort},abortConnect=false,connectRetry=5,connectTimeout=5000,syncTimeout=5000";
            await WaitForRedisReadinessAsync("127.0.0.1", redisHostPort, TimeSpan.FromSeconds(30));
            _ = CreateClient();
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
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Keycloak:Authority"] = "https://localhost:8443/realms/sentinel",
                    ["Keycloak:Audience"] = "sentinel-api",
                    ["Keycloak:RequireHttpsMetadata"] = "false",
                    ["ConnectionStrings:Redis"] = _redisConnectionString,
                    ["Sentinel:Redis:EndPoint"] = _redisConnectionString,
                    ["Sentinel:Redis:EnableInMemoryFallback"] = "true",
                    ["SdJwt:Enabled"] = "true",
                    ["SdJwt:RequireKeyBindingNonce"] = "false",
                    ["Sentinel:Security:Captcha:SecretKey"] = "0x4AAAAAAABB-MOCK-SECRET",
                    ["Sentinel:Security:Captcha:Enabled"] = "false"
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

                services.AddSingleton(new RedisOptions
                {
                    EndPoint = _redisConnectionString
                });

                services.AddSingleton<IDistributedCache>(_ =>
                    new RedisCache(Options.Create(new RedisCacheOptions { Configuration = _redisConnectionString })));

                services.AddSingleton<IConnectionMultiplexer>(_ =>
                {
                    var options = ConfigurationOptions.Parse(_redisConnectionString);
                    options.AbortOnConnectFail = false;
                    return ConnectionMultiplexer.Connect(options);
                });

                var redisConfig = new ConfigurationBuilder()
                    .AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["EndPoint"] = _redisConnectionString,
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

        private async ValueTask DisposeAsyncCore() => await _redisContainer.DisposeAsync();
    }

    private sealed class TestOpenIdConfigurationManager(SecurityKey signingKey)
        : IConfigurationManager<OpenIdConnectConfiguration>
    {
        private readonly OpenIdConnectConfiguration _configuration = new()
        {
            Issuer = "https://localhost:8443/realms/sentinel"
        };

        public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
        {
            _configuration.SigningKeys.Clear();
            _configuration.SigningKeys.Add(signingKey);
            return Task.FromResult(_configuration);
        }

        public void RequestRefresh()
        {
        }
    }
}
