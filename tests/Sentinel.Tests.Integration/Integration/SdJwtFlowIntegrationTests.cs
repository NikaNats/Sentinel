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
using Sentinel.Tests.Shared.Fixtures;
using StackExchange.Redis;
using Testcontainers.Redis;

namespace Sentinel.Tests.Integration;

public sealed class SdJwtFlowIntegrationTests : IClassFixture<SdJwtFlowIntegrationTests.SdJwtApiFactory>
{
    private readonly HttpClient client;

    public SdJwtFlowIntegrationTests(SdJwtApiFactory factory)
    {
        client = factory.CreateClient();
    }

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

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

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

    private static string ComputeDisclosureDigest(string disclosure)
    {
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(disclosure)));
    }

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
        private readonly RedisContainer redisContainer;
        private string redisConnectionString = string.Empty;

        public SdJwtApiFactory()
        {
            redisContainer = new RedisBuilder("redis:7.4-alpine")
                .WithPortBinding(6379, true)
                .Build();
        }

        public async ValueTask InitializeAsync()
        {
            await redisContainer.StartAsync();
            var redisHostPort = redisContainer.GetMappedPublicPort(6379);
            redisConnectionString =
                $"localhost:{redisHostPort},abortConnect=false,connectRetry=5,connectTimeout=5000,syncTimeout=5000";
            await WaitForRedisReadinessAsync("127.0.0.1", redisHostPort, TimeSpan.FromSeconds(30));
            _ = CreateClient();
        }

        ValueTask IAsyncDisposable.DisposeAsync() => new(DisposeAsyncCore());

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
                    ["SdJwt:Enabled"] = "true",
                    ["SdJwt:RequireKeyBindingNonce"] = "false"
                });
            });

            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IDistributedCache>();
                services.RemoveAll<IConnectionMultiplexer>();
                services.RemoveAll<IConfigurationManager<OpenIdConnectConfiguration>>();

                services.AddSingleton<IDistributedCache>(_ =>
                    new RedisCache(Options.Create(new RedisCacheOptions { Configuration = redisConnectionString })));

                services.AddSingleton<IConnectionMultiplexer>(_ =>
                {
                    var options = ConfigurationOptions.Parse(redisConnectionString);
                    options.AbortOnConnectFail = false;
                    return ConnectionMultiplexer.Connect(options);
                });

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

        private async Task DisposeAsyncCore()
        {
            await redisContainer.DisposeAsync();
            await base.DisposeAsync();
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
