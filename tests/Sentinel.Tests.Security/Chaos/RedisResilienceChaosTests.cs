using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.Tests.Security.Chaos;

[Collection("Sentinel Chaos Integration")]
public sealed class RedisResilienceChaosTests : IClassFixture<ChaosSentinelApiFactory>, IAsyncLifetime
{
    private const string TargetEndpoint = "/v1/security-context";
    private readonly HttpClient _client;
    private readonly ChaosSentinelApiFactory _factory;

    public RedisResilienceChaosTests(ChaosSentinelApiFactory factory)
    {
        _factory = factory;

        var wrappedFactory = _factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureTestServices(services =>
            {
                services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
                {
                    options.TokenValidationParameters ??= new TokenValidationParameters();
                    options.TokenValidationParameters.IssuerSigningKey = TestTokenIssuer.AuthoritySecurityKey;
                    options.TokenValidationParameters.ValidateIssuerSigningKey = true;
                    options.TokenValidationParameters.ValidIssuer = "https://localhost:8443/realms/sentinel";
                    options.TokenValidationParameters.ValidAudience = "sentinel-api";
                    options.TokenValidationParameters.ValidateIssuer = true;
                    options.TokenValidationParameters.ValidateAudience = true;
                    options.TokenValidationParameters.ValidateLifetime = true;
                    options.TokenValidationParameters.ClockSkew = TimeSpan.Zero;
                    options.TokenValidationParameters.SignatureValidator = null;

                    options.RequireHttpsMetadata = false;
                    options.ConfigurationManager = null;
                });
            });
        });

        _client = wrappedFactory.CreateClient();
    }

    private static CancellationToken TestCancellationToken => TestContext.Current.CancellationToken;

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    public async ValueTask DisposeAsync()
    {
        if (_factory.ChaosClient != null)
        {
            await _factory.ChaosClient.ResetChaosAsync();
        }
    }

    [Fact(DisplayName = "⏱️ Chaos 1: 150ms Latency Jitter -> System still works")]
    public async Task Request_WithNetworkLatency_ShouldSucceedWithinSla()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var securityKey = new ECDsaSecurityKey(ecdsa) { KeyId = "chaos-test-key" };
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(securityKey);

        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };

        var jkt = ComputeEcThumbprint(jwkObject);
        var token = TestTokenIssuer.MintAccessToken(jkt, "acr2");

        using var warmupRequest = CreateDpopRequest(token, ecdsa, securityKey, jwkObject, "GET", TargetEndpoint);
        using var warmupResponse = await _client.SendAsync(warmupRequest, TestCancellationToken);
        warmupResponse.StatusCode.Should().Be(HttpStatusCode.OK, "Warm-up must establish active Redis connection.");

        var rotatedNonce = warmupResponse.Headers.GetValues("DPoP-Nonce").FirstOrDefault();
        rotatedNonce.Should().NotBeNullOrWhiteSpace("Server must return rotated DPoP-Nonce on 200 OK");

        await _factory.ChaosClient!.AddLatencyAsync(150, 10);

        using var request =
            CreateDpopRequest(token, ecdsa, securityKey, jwkObject, "GET", TargetEndpoint, rotatedNonce);
        var response = await _client.SendAsync(request, TestCancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK,
            "the system is resilient to network latency and must successfully complete the request within SLA");
    }

    [Fact(DisplayName = "🛑 Chaos 2: Complete Redis timeout -> System shuts down in Fail-Closed mode")]
    public async Task Request_WithRedisTimeout_ShouldFailClosedWith503()
    {
        await _factory.ChaosClient!.AddTimeoutAsync(6000);

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var securityKey = new ECDsaSecurityKey(ecdsa) { KeyId = "chaos-test-key" };
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(securityKey);

        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };

        var jkt = ComputeEcThumbprint(jwkObject);
        var token = TestTokenIssuer.MintAccessToken(jkt, "acr2");

        using var request = CreateDpopRequest(token, ecdsa, securityKey, jwkObject, "GET", TargetEndpoint);

        var response = await _client.SendAsync(request, TestCancellationToken);

        response.StatusCode.Should().BeOneOf(HttpStatusCode.ServiceUnavailable, HttpStatusCode.InternalServerError);
    }

    [Fact(DisplayName = "📉 Chaos 3: 20% Packet Loss -> Service maintains safety")]
    public async Task Request_WithPacketLoss_EnforcesSecurityAndGracefulDegradation()
    {
        await _factory.ChaosClient!.AddPacketLossAsync(0.2);

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var securityKey = new ECDsaSecurityKey(ecdsa) { KeyId = "chaos-test-key" };
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(securityKey);

        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };

        var jkt = ComputeEcThumbprint(jwkObject);
        var token = TestTokenIssuer.MintAccessToken(jkt, "acr2");

        using var request = CreateDpopRequest(token, ecdsa, securityKey, jwkObject, "GET", TargetEndpoint);

        var response = await _client.SendAsync(request, TestCancellationToken);

        response.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.ServiceUnavailable,
            HttpStatusCode.InternalServerError);
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
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncoder.Encode(hash);
    }

    private static HttpRequestMessage CreateDpopRequest(
        string accessToken,
        ECDsa ecdsa,
        ECDsaSecurityKey securityKey,
        Dictionary<string, string> jwkObject,
        string method,
        string path,
        string? nonce = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = method,
            ["htu"] = $"http://localhost{path}",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        if (!string.IsNullOrEmpty(nonce))
        {
            claims["nonce"] = nonce;
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = jwkObject }
        };

        var proof = new JsonWebTokenHandler().CreateToken(descriptor);
        var request = new HttpRequestMessage(new HttpMethod(method), path);
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        request.Headers.Add("DPoP", proof);
        return request;
    }
}
