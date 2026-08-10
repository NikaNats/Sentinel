using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Keycloak.Dpop;
using Xunit;

namespace Sentinel.Tests.Unit.Keycloak;

public sealed class KeycloakDpopProofFactoryTests
{
    private const string Htu = "https://keycloak.local/realms/sentinel/protocol/openid-connect/token";
    private const string PostMethod = "POST";
    private const string AccessToken = "eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig";

    private readonly FakeTimeProvider _timeProvider;
    private readonly KeycloakDpopProofFactory _factory;

    public KeycloakDpopProofFactoryTests()
    {
        // Deterministic time provider prevents flaky iat assertions
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        _factory = new KeycloakDpopProofFactory(_timeProvider);
    }

    [Fact]
    public void CreateProof_ReturnsRfc9449DpopJwt()
    {
        var proof = _factory.CreateProof(PostMethod, Htu);
        var (header, payload) = DecodeJwtParts(proof);

        header.GetProperty("typ").GetString().Should().Be("dpop+jwt");
        header.GetProperty("alg").GetString().Should().Be("PS256");

        var jwk = header.GetProperty("jwk");
        jwk.GetProperty("kty").GetString().Should().Be("RSA");
        jwk.GetProperty("n").GetString().Should().NotBeNullOrWhiteSpace();
        jwk.GetProperty("e").GetString().Should().NotBeNullOrWhiteSpace();

        payload.GetProperty("htm").GetString().Should().Be(PostMethod);
        payload.GetProperty("htu").GetString().Should().Be(Htu);
        payload.GetProperty("jti").GetString().Should().NotBeNullOrWhiteSpace();

        var iat = payload.GetProperty("iat").GetInt64();
        iat.Should().Be(_timeProvider.GetUtcNow().ToUnixTimeSeconds());

        payload.TryGetProperty("ath", out _).Should().BeFalse("ath should not be present without an access token");
    }

    [Fact]
    public void CreateProof_ProducesUniqueJtiPerCall()
    {
        var first = _factory.CreateProof(PostMethod, Htu);
        var second = _factory.CreateProof(PostMethod, Htu);

        var (_, firstPayload) = DecodeJwtParts(first);
        var (_, secondPayload) = DecodeJwtParts(second);

        firstPayload.GetProperty("jti").GetString().Should().NotBe(secondPayload.GetProperty("jti").GetString());
    }

    [Fact]
    public void CreateProof_SignatureVerifiesWithPssSha256()
    {
        var proof = _factory.CreateProof(PostMethod, Htu);
        var segments = proof.Split('.');
        segments.Length.Should().Be(3);

        var (header, _) = DecodeJwtParts(proof);
        var signatureBytes = Base64UrlEncoder.DecodeBytes(segments[2]);
        var signedData = Encoding.UTF8.GetBytes($"{segments[0]}.{segments[1]}");

        var jwk = header.GetProperty("jwk");
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = Base64UrlEncoder.DecodeBytes(jwk.GetProperty("n").GetString()!),
            Exponent = Base64UrlEncoder.DecodeBytes(jwk.GetProperty("e").GetString()!)
        });

        var verified = rsa.VerifyData(signedData, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        verified.Should().BeTrue("proof signature must verify with the advertised JWK (PS256)");
    }

    [Fact]
    public void CreateProof_WithAccessToken_IncludesAthClaim()
    {
        var proof = _factory.CreateProof(PostMethod, Htu, AccessToken);
        var (_, payload) = DecodeJwtParts(proof);

        var expectedAth = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(AccessToken)));
        payload.GetProperty("ath").GetString().Should().Be(expectedAth);
    }

    [Fact]
    public async Task DpopProofDelegatingHandler_AddsProofWhenHeaderAbsent()
    {
        HttpRequestMessage? capturedRequest = null;
        using var innerHandler = new StubHttpMessageHandler(req =>
        {
            capturedRequest = req;
            return Task.FromResult(HttpStatusCode.OK);
        });

        using var handler = new DpopProofDelegatingHandler(_factory) { InnerHandler = innerHandler };
        using var client = new HttpClient(handler) { BaseAddress = new Uri("https://keycloak.local") };

        using var request = new HttpRequestMessage(HttpMethod.Post, "/realms/sentinel/protocol/openid-connect/token");
        await client.SendAsync(request, TestContext.Current.CancellationToken);

        capturedRequest.Should().NotBeNull();
        var proofHeader = capturedRequest!.Headers.GetValues("DPoP").Single();

        var (_, payload) = DecodeJwtParts(proofHeader);
        payload.GetProperty("htu").GetString().Should().Be("https://keycloak.local/realms/sentinel/protocol/openid-connect/token");
    }

    [Fact]
    public async Task DpopProofDelegatingHandler_PreservesCallerSuppliedProof()
    {
        const string callerProof = "existing-proof";
        HttpRequestMessage? capturedRequest = null;

        using var innerHandler = new StubHttpMessageHandler(req =>
        {
            capturedRequest = req;
            return Task.FromResult(HttpStatusCode.OK);
        });

        using var handler = new DpopProofDelegatingHandler(_factory) { InnerHandler = innerHandler };
        using var client = new HttpClient(handler) { BaseAddress = new Uri("https://keycloak.local") };

        using var request = new HttpRequestMessage(HttpMethod.Post, "/realms/sentinel/protocol/openid-connect/token");
        request.Headers.Add("DPoP", callerProof);

        await client.SendAsync(request, TestContext.Current.CancellationToken);

        capturedRequest.Should().NotBeNull();
        capturedRequest!.Headers.GetValues("DPoP").Single().Should().Be(callerProof);
    }

    private static (JsonElement Header, JsonElement Payload) DecodeJwtParts(string jwt)
    {
        var segments = jwt.Split('.');
        segments.Length.Should().Be(3);

        // Use using blocks to prevent memory leaks, Clone() ensures the elements survive document disposal
        using var headerDoc = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(segments[0]));
        using var payloadDoc = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(segments[1]));

        return (headerDoc.RootElement.Clone(), payloadDoc.RootElement.Clone());
    }

    /// <summary>
    /// High-performance stub avoiding ContinueWith state-machine allocations for synchronous mock returns.
    /// </summary>
    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, Task<HttpStatusCode>> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var statusCodeTask = responder(request);
            if (statusCodeTask.IsCompletedSuccessfully)
            {
                return Task.FromResult(new HttpResponseMessage(statusCodeTask.Result) { RequestMessage = request });
            }

            return SendAsyncCore(statusCodeTask, request);
        }

        private static async Task<HttpResponseMessage> SendAsyncCore(Task<HttpStatusCode> statusCodeTask, HttpRequestMessage request)
        {
            var statusCode = await statusCodeTask;
            return new HttpResponseMessage(statusCode) { RequestMessage = request };
        }
    }
}
