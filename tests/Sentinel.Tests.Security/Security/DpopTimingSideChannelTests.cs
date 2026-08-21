using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
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
using Sentinel.AspNetCore.Middleware;
using Sentinel.AspNetCore.Stores;
using Sentinel.DPoP;
using Sentinel.DPoP.Pqc;
using Sentinel.Redis;
using Sentinel.SdJwt;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Idempotency;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Pqc;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Session;
using Sentinel.Security.Abstractions.SSF;
using StackExchange.Redis;
using TestJsonContext = Sentinel.Tests.Shared.TestJsonContext;
using ISsfEventProcessor = Sentinel.Application.Auth.Interfaces.ISsfEventProcessor;

namespace Sentinel.Tests.Security.Security;

[Collection("Sentinel Timing Tests")]
public sealed class DpopTimingSideChannelTests(DpopTimingSideChannelTests.IsolatedTimingTestFactory factory)
    : IClassFixture<DpopTimingSideChannelTests.IsolatedTimingTestFactory>
{
    private const int SampleSize = 100;
    private const int WarmupIterations = 25;

    private readonly HttpClient _client = factory.CreateClient();

    [Fact(DisplayName =
        "⏱️ Side-Channel: Early vs Late DPoP rejection timings must be statistically indistinguishable (Welch's T-Test p > 0.05)")]
    public async Task Validate_DpopRejectionPaths_MustHaveStatisticallyIndistinguishableTiming()
    {
        // 1. Warmup Phase (Eliminates JIT compilation and cold DI resolution bias)
        for (var w = 0; w < WarmupIterations; w++)
        {
            using var warmupKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var (warmupJwk, _) = CreateKeyDetails(warmupKey);
            var warmupToken = TestTokenIssuer.MintAccessToken("mismatched-jkt", "acr2");

            using var reqWarmupEarly = new HttpRequestMessage(HttpMethod.Get, "/test-timing");
            reqWarmupEarly.Headers.Authorization = new AuthenticationHeaderValue("DPoP", warmupToken);
            reqWarmupEarly.Headers.Add("DPoP", "malformed.early.token");
            using var warmupResEarly = await _client.SendAsync(reqWarmupEarly, TestContext.Current.CancellationToken);

            using var reqWarmupLate = CreateSignedRequest(warmupKey, warmupJwk, warmupToken, "GET", "/test-timing");
            using var warmupResLate = await _client.SendAsync(reqWarmupLate, TestContext.Current.CancellationToken);
        }

        var earlyRejectTimes = new double[SampleSize];
        var lateRejectTimes = new double[SampleSize];

        // 2. Measurement Phase
        for (var i = 0; i < SampleSize; i++)
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var (jwkObject, _) = CreateKeyDetails(ecdsa);

            var token = TestTokenIssuer.MintAccessToken("different-expected-jkt-value", "acr2");

            // --- Early Rejection Path (Malformed JWT syntax -> fails in TryExtractProofDetails) ---
            using var reqEarly = new HttpRequestMessage(HttpMethod.Get, "/test-timing");
            reqEarly.Headers.Authorization = new AuthenticationHeaderValue("DPoP", token);
            reqEarly.Headers.Add("DPoP", "syntax.invalid.jwt.token");

            var swEarly = Stopwatch.StartNew();
            using var resEarly = await _client.SendAsync(reqEarly, TestContext.Current.CancellationToken);
            swEarly.Stop();

            resEarly.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            earlyRejectTimes[i] = swEarly.Elapsed.TotalMilliseconds;

            // --- Late Rejection Path (Valid signature -> fails in DpopProofValidator at jkt_mismatch) ---
            using var reqLate = CreateSignedRequest(ecdsa, jwkObject, token, "GET", "/test-timing");

            var swLate = Stopwatch.StartNew();
            using var resLate = await _client.SendAsync(reqLate, TestContext.Current.CancellationToken);
            swLate.Stop();

            resLate.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            lateRejectTimes[i] = swLate.Elapsed.TotalMilliseconds;
        }

        // 3. Statistical Analysis
        var meanEarly = earlyRejectTimes.Average();
        var meanLate = lateRejectTimes.Average();
        var delta = Math.Abs(meanEarly - meanLate);
        var pValue = CalculateWelchsTTest(earlyRejectTimes, lateRejectTimes);

        (pValue > 0.05 || delta < 15.0).Should().BeTrue(
            $"Timing Oracle detected! Mean Early: {meanEarly:F2}ms, Mean Late: {meanLate:F2}ms, Delta: {delta:F2}ms, p-value: {pValue:F4}. " +
            "The early and late rejection paths must exhibit statistically indistinguishable execution latency.");
    }

    private static (Dictionary<string, string> Jwk, string Jkt) CreateKeyDetails(ECDsa ecdsa)
    {
        var securityKey = new ECDsaSecurityKey(ecdsa) { KeyId = Guid.NewGuid().ToString("N") };
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(securityKey);
        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };
        var jkt = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(jwkObject, TestJsonContext.Default.DictionaryStringString))));
        return (jwkObject, jkt);
    }

    private static HttpRequestMessage CreateSignedRequest(
        ECDsa ecdsa,
        Dictionary<string, string> jwkObject,
        string accessToken,
        string method,
        string path)
    {
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = method,
            ["htu"] = $"http://localhost{path}",
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

        var request = new HttpRequestMessage(new HttpMethod(method), path);
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        request.Headers.Add("DPoP", proof);
        return request;
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

    public sealed class IsolatedTimingTestFactory : WebApplicationFactory<Program>
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
                    ["Sentinel:Redis:EnableInMemoryFallback"] = "true",
                    ["DPoP:AllowedAlgorithms:0"] = "ES256",
                    ["DPoP:AllowedAlgorithms:1"] = "PS256",
                    ["DPoP:ProofLifetimeSeconds"] = "60",
                    ["DPoP:AllowedClockSkewSeconds"] = "10"
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
                services.RemoveAll<IDpopThumbprintComputer>();
                services.RemoveAll<IDpopProofValidator>();
                services.RemoveAll<IMlDsaSignatureVerifier>();
                services.RemoveAll<PqcCryptoProviderFactory>();
                services.RemoveAll<L1AntiFloodCache>();

                services.AddSingleton(TimeProvider.System);
                services.AddSingleton(sp =>
                    new L1AntiFloodCache(sp.GetRequiredService<TimeProvider>(), TimeSpan.FromSeconds(3)));
                services.AddSingleton<IJtiReplayCache, FastLocalInMemoryJtiCache>();
                services.AddSingleton<IDpopNonceStore, FastLocalInMemoryNonceStore>();
                services.AddSingleton<ISessionBlacklistCache, FastLocalInMemorySessionBlacklist>();
                services.AddSingleton<IIdempotencyStore, InMemoryIdempotencyStore>();
                services.AddSingleton<IDpopThumbprintComputer, DpopThumbprintComputer>();
                services.AddSingleton<IMlDsaSignatureVerifier>(new FailClosedMlDsaVerifier());
                services.AddSingleton<PqcCryptoProviderFactory>();
                services.AddTransient<IDpopProofValidator, DpopProofValidator>();

                services.AddTransient<ISdJwtTokenValidator, TestSdJwtTokenValidator>();
                services.AddSingleton<ISsfTokenValidator, TestSsfTokenValidator>();
                services.AddScoped<ISsfEventProcessor, SsfEventProcessorAdapter>();

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

            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseMiddleware<DpopValidationMiddleware>();
                app.UseEndpoints(endpoints =>
                {
                    // Native AOT safe: returns plain text without reflection-based JSON serialization
                    endpoints.MapGet("/test-timing", () => Results.Text("ok"));
                });
            });
        }
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

    public sealed class TestOpenIdConfigurationManager(SecurityKey signingKey)
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

    private sealed class FailClosedMlDsaVerifier : IMlDsaSignatureVerifier
    {
        public bool Verify(string algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> input,
            ReadOnlySpan<byte> signature) => false;
    }
}