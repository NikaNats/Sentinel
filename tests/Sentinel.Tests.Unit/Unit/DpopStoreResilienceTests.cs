using System.Security.Cryptography;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Sentinel.AspNetCore.Middleware;
using Sentinel.AspNetCore.Stores;
using Sentinel.DPoP;
using Sentinel.DPoP.Pqc;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Exceptions;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Pqc;
using Sentinel.Security.Abstractions.Results;
using Xunit;

namespace Sentinel.Tests.Unit.Unit;

/// <summary>
///     Defect D regression tests: when the backing DPoP nonce store experiences an
///     infrastructure outage, the middleware must fail closed with HTTP 503 + Retry-After
///     instead of emitting an endless 401 use_dpop_nonce retry storm.
/// </summary>
public sealed class DpopStoreResilienceTests
{
    private const string TargetHost = "api.sentinel.io";
    private const string TargetPath = "/resource";
    private const string TargetUrl = $"https://{TargetHost}{TargetPath}";

    private readonly IOptions<DPoPOptions> _dpopOptions;
    private readonly ECDsa _ecdsa;
    private readonly L1AntiFloodCache _l1Cache;
    private readonly Dictionary<string, string> _publicJwk;
    private readonly ECDsaSecurityKey _securityKey;
    private readonly IServiceProvider _serviceProvider;
    private readonly IDpopThumbprintComputer _thumbprintComputer;
    private readonly TimeProvider _timeProvider;

    public DpopStoreResilienceTests()
    {
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _securityKey = new ECDsaSecurityKey(_ecdsa) { KeyId = "test-resilience-key" };

        var parameters = _ecdsa.ExportParameters(false);
        _publicJwk = new Dictionary<string, string>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(
                parameters.Q.X ?? throw new InvalidOperationException("Failed to export X coordinate.")),
            ["y"] = Base64UrlEncoder.Encode(
                parameters.Q.Y ?? throw new InvalidOperationException("Failed to export Y coordinate.")),
            ["kid"] = "test-resilience-key"
        };

        _thumbprintComputer = new DpopThumbprintComputer();
        _timeProvider = TimeProvider.System;
        _l1Cache = new L1AntiFloodCache(_timeProvider, TimeSpan.FromSeconds(3));

        _dpopOptions = Microsoft.Extensions.Options.Options.Create(new DPoPOptions
        {
            AllowedAlgorithms = ["ES256"]
        });

        var services = new ServiceCollection();
        services.AddSingleton<ILogger<DpopValidationMiddleware>>(NullLogger<DpopValidationMiddleware>.Instance);
        services.AddSingleton<IMlDsaSignatureVerifier>(new FailClosedMlDsaVerifier());
        services.AddSingleton<PqcCryptoProviderFactory>();
        _serviceProvider = services.BuildServiceProvider();
    }

    [Fact(DisplayName =
        "🛡️ Defect D Verification: Infra outage → NonceStoreUnavailableException → HTTP 503 + Retry-After (fail-closed)")]
    public async Task InvokeAsync_WhenNonceStoreFails_Returns503WithRetryAfter()
    {
        // Arrange
        var dpopProof = CreateValidDpopProof("POST", TargetUrl);
        var context = CreateHttpContextWithHeaders("DPoP access-token-abc", dpopProof);

        var validatorMock = new Mock<IDpopProofValidator>(MockBehavior.Strict);
        var nonceStoreMock = new Mock<IDpopNonceStore>(MockBehavior.Strict);

        // Simulate Redis cluster outage: every read fails closed with the fail-closed exception type.
        nonceStoreMock
            .Setup(x => x.GetNonceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new NonceStoreUnavailableException("Redis cluster unreachable during GET"));

        RequestDelegate next = _ => throw new InvalidOperationException("Pipeline must not proceed on infrastructure failure");

        var middleware =
            new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache,
                NullLogger<DpopValidationMiddleware>.Instance, _dpopOptions);

        // Act
        await middleware.InvokeAsync(context, validatorMock.Object, nonceStoreMock.Object);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status503ServiceUnavailable);
        context.Response.Headers.Should().ContainKey("Retry-After");
        context.Response.Headers["Retry-After"].ToString().Should().Be("5");

        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(context.Response.Body);
        var responseBody = await reader.ReadToEndAsync();

        responseBody.Should().Contain("/errors/service-unavailable");
        responseBody.Should().Contain("Security infrastructure unavailable");

        context.Response.Headers.WWWAuthenticate.ToString().Should().NotContain("use_dpop_nonce",
            "The outage must NOT be misclassified as a client nonce mismatch (that would cause an infinite 401 loop).");
    }

    [Fact(
    DisplayName =
        "🛡️ Defect D Verification: Infra store failure during nonce store-write also surfaces as 503")]
    public async Task InvokeAsync_WhenNonceStoreWriteFails_ReturnsHttp503()
    {
        // Arrange
        const string expectedNonce = "active-nonce-123";

        var dpopProof = CreateValidDpopProof("POST", TargetUrl, expectedNonce);
        var context = CreateHttpContextWithHeaders("DPoP access-token-abc", dpopProof);

        var validatorMock = new Mock<IDpopProofValidator>(MockBehavior.Strict);
        var nonceStoreMock = new Mock<IDpopNonceStore>(MockBehavior.Strict);

        nonceStoreMock
            .Setup(x => x.GetNonceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedNonce);

        validatorMock
            .Setup(x => x.ValidateAsync(It.IsAny<DpopValidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SecurityResultFactory.Failure<DpopValidationSuccess>("use_dpop_nonce"));

        // Store outage on the challenge nonce persistence.
        nonceStoreMock
            .Setup(x => x.SetNonceAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new NonceStoreUnavailableException("Redis cluster unreachable during nonce store"));

        RequestDelegate next = _ => throw new InvalidOperationException("Pipeline must not proceed on infrastructure failure");

        var middleware =
            new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache,
                NullLogger<DpopValidationMiddleware>.Instance, _dpopOptions);

        // Act
        await middleware.InvokeAsync(context, validatorMock.Object, nonceStoreMock.Object);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status503ServiceUnavailable);
        context.Response.Headers.Should().ContainKey("Retry-After");
    }

    private string CreateValidDpopProof(string method, string url, string? nonce = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = method,
            ["htu"] = url,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        if (!string.IsNullOrEmpty(nonce))
        {
            claims["nonce"] = nonce;
        }

        var jwtHandler = new JsonWebTokenHandler();
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(_securityKey, SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = _publicJwk
            }
        };

        return jwtHandler.CreateToken(descriptor);
    }

    private DefaultHttpContext CreateHttpContextWithHeaders(string authHeader, string dpopHeader)
    {
        var context = new DefaultHttpContext { RequestServices = _serviceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("api.sentinel.io");
        context.Request.Path = TargetPath;
        context.Request.Method = HttpMethods.Post;
        context.Request.Headers.Authorization = authHeader;
        context.Request.Headers["DPoP"] = dpopHeader;
        context.Response.Body = new MemoryStream();
        return context;
    }

    private sealed class FailClosedMlDsaVerifier : IMlDsaSignatureVerifier
    {
        public bool Verify(string algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> input,
            ReadOnlySpan<byte> signature) => false;
    }
}