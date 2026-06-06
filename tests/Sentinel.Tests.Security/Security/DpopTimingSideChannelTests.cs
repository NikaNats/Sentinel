using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Sentinel.AspNetCore.Stores;
using Sentinel.Redis;
using Sentinel.SdJwt;
using Sentinel.Security.Abstractions.Idempotency;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Security;
using Sentinel.Security.Abstractions.Session;
using Sentinel.Security.Abstractions.SSF;
using StackExchange.Redis;
using ISsfEventProcessor = Sentinel.Application.Auth.Interfaces.ISsfEventProcessor;

namespace Sentinel.Tests.Security.Security;

[Collection("Sentinel Timing Tests")]
public sealed class DpopTimingSideChannelTests(TimingTestApiFactory factory) : IClassFixture<TimingTestApiFactory>
{
    private const int SampleSize = 500;
    private readonly HttpClient _client = factory.CreateClient();

    [Fact(DisplayName = "🔐 Mathematical Assurance: Welch's T-Test Proves the Absence of a timing-oracle")]
    public async Task Validate_DpopRejectionPaths_MustHaveStatisticallyIndistinguishableTiming()
    {
        var earlyRejectTimes = new double[SampleSize];
        var lateRejectTimes = new double[SampleSize];

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var securityKey = new ECDsaSecurityKey(ecdsa) { KeyId = "side-channel-key" };
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(securityKey);
        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };

        var jkt = "mismatched-jkt-value-abc";
        var token = TestTokenIssuer.MintAccessToken(jkt, "acr2");

        for (var i = 0; i < SampleSize; i++)
        {
            using var reqEarly = new HttpRequestMessage(HttpMethod.Get, "/v1/profile");
            reqEarly.Headers.Authorization = new AuthenticationHeaderValue("DPoP", token);
            reqEarly.Headers.Add("DPoP", "invalid.dpop.token");

            var swEarly = Stopwatch.StartNew();
            using var resEarly = await _client.SendAsync(reqEarly, CancellationToken.None);
            swEarly.Stop();

            resEarly.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            earlyRejectTimes[i] = swEarly.Elapsed.TotalMilliseconds;

            using var reqLate = CreateSignedRequest(ecdsa, jwkObject, token, "GET", "/v1/profile");

            var swLate = Stopwatch.StartNew();
            using var resLate = await _client.SendAsync(reqLate, CancellationToken.None);
            swLate.Stop();

            resLate.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            lateRejectTimes[i] = swLate.Elapsed.TotalMilliseconds;
        }

        var pValue = CalculateWelchsTTest(earlyRejectTimes, lateRejectTimes);

        var meanEarly = earlyRejectTimes.Average();
        var meanLate = lateRejectTimes.Average();
        var difference = Math.Abs(meanEarly - meanLate);

        (pValue > 0.05 || difference < 5.0).Should().BeTrue(
            $"Timing Oracle detected! Mean Early: {meanEarly:F4}ms, Mean Late: {meanLate:F4}ms, Delta: {difference:F4}ms, p-value: {pValue:F4}");
    }

    private static double CalculateWelchsTTest(double[] sample1, double[] sample2)
    {
        var mean1 = sample1.Average();
        var mean2 = sample2.Average();

        var sum1 = sample1.Select(x => Math.Pow(x - mean1, 2)).Sum();
        var sum2 = sample2.Select(x => Math.Pow(x - mean2, 2)).Sum();

        var var1 = sum1 / (sample1.Length - 1);
        var var2 = sum2 / (sample2.Length - 1);

        double n1 = sample1.Length;
        double n2 = sample2.Length;

        var t = (mean1 - mean2) / Math.Sqrt(var1 / n1 + var2 / n2);

        var dfNumerator = Math.Pow(var1 / n1 + var2 / n2, 2);
        var dfDenominator = Math.Pow(var1 / n1, 2) / (n1 - 1) + Math.Pow(var2 / n2, 2) / (n2 - 1);
        var df = dfNumerator / dfDenominator;

        return GetTwoTailedPValue(Math.Abs(t), df);
    }

    private static double GetTwoTailedPValue(double t, double df)
    {
        var x = t / Math.Sqrt(2.0);
        var erf = Erf(x);
        return 1.0 - erf;
    }

    private static double Erf(double x)
    {
        var a1 = 0.254829592;
        var a2 = -0.284496736;
        var a3 = 1.421413741;
        var a4 = -1.453152027;
        var a5 = 1.061405429;
        var p = 0.3275911;

        var sign = x < 0 ? -1 : 1;
        x = Math.Abs(x);

        var t = 1.0 / (1.0 + p * x);
        var y = 1.0 - ((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t * Math.Exp(-x * x);

        return sign * y;
    }

    private static HttpRequestMessage CreateSignedRequest(
        ECDsa ecdsa,
        Dictionary<string, string> jwkObject,
        string accessToken,
        string method,
        string url)
    {
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = method,
            ["htu"] = $"http://localhost{url}",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(ecdsa),
                SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = jwkObject
            }
        };

        var proof = new JsonWebTokenHandler().CreateToken(descriptor);

        var request = new HttpRequestMessage(new HttpMethod(method), url);
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        request.Headers.Add("DPoP", proof);
        return request;
    }
}

public class TimingTestApiFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Keycloak:Authority"] = "https://localhost:8443/realms/sentinel",
                ["Keycloak:Audience"] = "sentinel-api",
                ["Keycloak:RequireHttpsMetadata"] = "false",
                ["ConnectionStrings:Redis"] = "localhost:6379",
                ["Sentinel:Redis:EndPoint"] = "localhost:6379",
                ["Sentinel:Redis:EnableInMemoryFallback"] = "true"
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

            services.AddSingleton<IJtiReplayCache, FastLocalInMemoryJtiCache>();
            services.AddSingleton<IDpopNonceStore, FastLocalInMemoryNonceStore>();
            services.AddSingleton<ISessionBlacklistCache, FastLocalInMemorySessionBlacklist>();
            services.AddSingleton<IIdempotencyStore, InMemoryIdempotencyStore>();
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

    private sealed class FastLocalInMemoryJtiCache : IJtiReplayCache
    {
        private readonly ConcurrentDictionary<string, DateTimeOffset> _jtis = new();

        public Task<bool> TryMarkUsedAsync(string jti, DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default) => Task.FromResult(_jtis.TryAdd(jti, expiresAt));

        public Task CleanupExpiredAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class FastLocalInMemoryNonceStore : IDpopNonceStore
    {
        private readonly ConcurrentDictionary<string, string> _nonces = new();

        public Task<string?> GetNonceAsync(string thumbprint, CancellationToken cancellationToken = default) =>
            Task.FromResult(_nonces.TryGetValue(thumbprint, out var val) ? val : null);

        public Task SetNonceAsync(string thumbprint, string nonce, DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default)
        {
            _nonces[thumbprint] = nonce;
            return Task.CompletedTask;
        }

        public Task CleanupExpiredAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<bool> ConsumeNonceIfMatchesAsync(string thumbprint, string expectedNonce,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(_nonces.TryRemove(new KeyValuePair<string, string>(thumbprint, expectedNonce)));
    }

    private sealed class FastLocalInMemorySessionBlacklist : ISessionBlacklistCache
    {
        private readonly ConcurrentDictionary<string, DateTimeOffset> _sessions = new();

        public Task BlacklistSessionAsync(string sessionId, DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default)
        {
            _sessions[sessionId] = expiresAt;
            return Task.CompletedTask;
        }

        public Task<bool> IsBlacklistedAsync(string sessionId, CancellationToken cancellationToken = default) =>
            Task.FromResult(_sessions.ContainsKey(sessionId));

        public Task CleanupExpiredAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}

file sealed class TestOpenIdConfigurationManager(SecurityKey signingKey)
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
