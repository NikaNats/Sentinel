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
using Sentinel.Tests.Shared;
using Sentinel.Tests.Shared.Fixtures;
using StackExchange.Redis;
using Testcontainers.Redis;

#pragma warning disable CA2213

namespace Sentinel.Tests.Integration;

public sealed class SsfIntegrationTests : IClassFixture<SsfIntegrationTests.SsfApiFactory>
{
    private readonly HttpClient client;

    public SsfIntegrationTests(SsfApiFactory factory)
    {
        client = factory.CreateClient();
    }

    [Fact]
    public async Task SessionRevokedEvent_BlacklistsSessionAndRejectsSubsequentAccess()
    {
        var sid = "ssf-session-1";
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ecdsa));
        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };
        var jkt = ComputeEcThumbprint(jwkObject);

        var preEventToken = TestTokenIssuer.MintAccessToken(jkt, sid: sid);
        using var preEventRequest = CreateDpopRequest(ecdsa, jwkObject, preEventToken,
            new Uri(client.BaseAddress!, "/v1/test/protected").ToString(), "/v1/test/protected");
        var preEventResponse = await client.SendAsync(preEventRequest, CancellationToken.None);
        Assert.Equal(HttpStatusCode.OK, preEventResponse.StatusCode);

        var setToken = CreateSetToken(sid);
        using var ssfRequest = new HttpRequestMessage(HttpMethod.Post, "/v1/ssf/events")
        {
            Content = new StringContent($$"""{"set":"{{setToken}}"}""", Encoding.UTF8, "application/json")
        };

        var ssfResponse = await client.SendAsync(ssfRequest, CancellationToken.None);
        Assert.Equal(HttpStatusCode.Accepted, ssfResponse.StatusCode);

        var postEventToken = TestTokenIssuer.MintAccessToken(jkt, sid: sid);
        using var postEventRequest = CreateDpopRequest(ecdsa, jwkObject, postEventToken,
            new Uri(client.BaseAddress!, "/v1/test/protected").ToString(), "/v1/test/protected");
        var postEventResponse = await client.SendAsync(postEventRequest, CancellationToken.None);

        Assert.Equal(HttpStatusCode.Unauthorized, postEventResponse.StatusCode);
    }

    [Fact]
    public async Task SessionRevokedEvent_WhenBlacklistStoreFails_ReturnsServerError()
    {
        await using var factory = new FailingSsfApiFactory();
        await factory.InitializeAsync();
        using var localClient = factory.CreateClient();

        var setToken = CreateSetToken("failing-sid");
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/ssf/events")
        {
            Content = new StringContent($$"""{"set":"{{setToken}}"}""", Encoding.UTF8, "application/json")
        };

        var response = await localClient.SendAsync(request, CancellationToken.None);

        Assert.True(response.StatusCode is HttpStatusCode.InternalServerError or HttpStatusCode.ServiceUnavailable);
    }

    private static HttpRequestMessage CreateDpopRequest(ECDsa key, Dictionary<string, string> jwkObject,
        string accessToken, string absoluteUrl, string relativeUrl)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["htm"] = "GET",
                ["htu"] = absoluteUrl,
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = jwkObject }
        };

        var request = new HttpRequestMessage(HttpMethod.Get, relativeUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        request.Headers.Add("DPoP", new JsonWebTokenHandler().CreateToken(descriptor));
        return request;
    }

    private static string CreateSetToken(string sid)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "https://localhost:8443/realms/sentinel",
            Audience = "sentinel-api",
            Claims = new Dictionary<string, object>
            {
                ["sub"] = "user-1",
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["events"] = new Dictionary<string, JsonElement>
                {
                    ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"] =
                        JsonSerializer.SerializeToElement(new Sentinel.Security.Abstractions.SSF.SessionRevokedPayload(sid, "user-1"))
                }
            },
            SigningCredentials =
                new SigningCredentials(TestTokenIssuer.AuthoritySecurityKey, SecurityAlgorithms.EcdsaSha256)
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static string ComputeEcThumbprint(Dictionary<string, string> jwk)
    {
        var canonical = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["crv"] = jwk["crv"],
            ["kty"] = jwk["kty"],
            ["x"] = jwk["x"],
            ["y"] = jwk["y"]
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

    public class SsfApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly RedisContainer redisContainer;
        private string redisConnectionString = string.Empty;

        public SsfApiFactory()
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

        // Overriding the base DisposeAsync method cleans up warnings and integrates properly with the pipeline.
        // Calling GC.SuppressFinalize(this) protects any derived types that introduce a native finalizer.
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
                    ["ConnectionStrings:Redis"] = redisConnectionString,
                    ["Sentinel:Redis:EndPoint"] = redisConnectionString,
                    ["Sentinel:Redis:EnableInMemoryFallback"] = "true",
                    ["Ssf:Enabled"] = "true",
                    ["Ssf:RequireAuthToken"] = "false"
                });
            });

            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IDistributedCache>();
                services.RemoveAll<IConnectionMultiplexer>();
                services.RemoveAll<IRedisConnectionProvider>();
                services.RemoveAll<Sentinel.Security.Abstractions.Idempotency.IIdempotencyStore>();
                services.RemoveAll<IConfigurationManager<OpenIdConnectConfiguration>>();
                services.RemoveAll<Sentinel.Security.Abstractions.Replay.IJtiReplayCache>();
                services.RemoveAll<Sentinel.Security.Abstractions.Nonce.IDpopNonceStore>();
                services.RemoveAll<Sentinel.Security.Abstractions.Session.ISessionBlacklistCache>();
                services.RemoveAll<RedisOptions>();

                services.AddSingleton(new RedisOptions
                {
                    EndPoint = redisConnectionString
                });

                services.AddSingleton<IDistributedCache>(_ =>
                    new RedisCache(Options.Create(new RedisCacheOptions { Configuration = redisConnectionString })));

                services.AddSingleton<IConnectionMultiplexer>(_ =>
                {
                    var options = ConfigurationOptions.Parse(redisConnectionString);
                    options.AbortOnConnectFail = false;
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
                services.AddTransient<Sentinel.SdJwt.ISdJwtTokenValidator, TestSdJwtTokenValidator>();
                services.AddSingleton<Sentinel.Security.Abstractions.SSF.ISsfTokenValidator, TestSsfTokenValidator>();
                services.AddScoped<Sentinel.Application.Auth.Interfaces.ISsfEventProcessor, SsfEventProcessorAdapter>();
                services.AddScoped<Sentinel.Security.Abstractions.Security.IAuthRevocationService, AuthRevocationServiceAdapter>();

                services.AddSingleton<Sentinel.Application.Common.Abstractions.IJtiReplayCache>(sp =>
                    new JtiReplayCacheAdapter(
                        sp.GetRequiredService<Sentinel.Security.Abstractions.Replay.IJtiReplayCache>(),
                        sp.GetService<TimeProvider>()));

                services.AddSingleton<Sentinel.Application.Common.Abstractions.ISessionBlacklistCache>(sp =>
                    new SessionBlacklistCacheAdapter(
                        sp.GetRequiredService<Sentinel.Security.Abstractions.Session.ISessionBlacklistCache>(),
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
            await redisContainer.DisposeAsync();
        }
    }
}

// 🟢 file-scoped კლასების გამოყენება, რაც სრულად გამორიცხავს ნებისმიერ კონფლიქტს სხვა ფაილებთან
file sealed class FailingSsfApiFactory : SsfIntegrationTests.SsfApiFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<Sentinel.Security.Abstractions.Session.ISessionBlacklistCache>();

            // 🟢 სწორი იმპლემენტაციის რეგისტრაცია აბსოლუტური ნეიმსფეისით
            services.AddSingleton<Sentinel.Security.Abstractions.Session.ISessionBlacklistCache, ThrowingSecuritySessionBlacklistCache>();

            // 🟢 სწორი აპლიკაციის ფენის ადაპტერის რეგისტრაცია
            services.AddSingleton<Sentinel.Application.Common.Abstractions.ISessionBlacklistCache>(sp =>
                new SessionBlacklistCacheAdapter(
                    sp.GetRequiredService<Sentinel.Security.Abstractions.Session.ISessionBlacklistCache>(),
                    sp.GetService<TimeProvider>()));
        });
    }
}

#pragma warning disable CA1822 
file sealed class ThrowingSecuritySessionBlacklistCache : Sentinel.Security.Abstractions.Session.ISessionBlacklistCache
{
    public Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        throw new InvalidOperationException("Simulated blacklist failure.");
    }

    public Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(false);
    }

    public Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }
}
#pragma warning restore CA1822

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
