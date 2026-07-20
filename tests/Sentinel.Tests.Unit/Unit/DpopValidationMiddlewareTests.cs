using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
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
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Pqc;
using Sentinel.Security.Abstractions.Results;

namespace Sentinel.Tests.Unit.Unit;

public sealed class DpopValidationMiddlewareTests : IDisposable
{
    private const string TestKeyId = "test-key-2026";
    private const string TargetHost = "api.sentinel.io";
    private const string TargetPath = "/resource";
    private const string TargetUrl = $"https://{TargetHost}{TargetPath}";

    private readonly IOptions<DPoPOptions> _dpopOptions;
    private readonly ECDsa _ecdsa;
    private readonly L1AntiFloodCache _l1Cache;
    private readonly ILogger<DpopValidationMiddleware> _logger;
    private readonly Mock<IDpopNonceStore> _nonceStoreMock;
    private readonly Dictionary<string, string> _publicJwk;
    private readonly ECDsaSecurityKey _securityKey;
    private readonly IServiceProvider _serviceProvider;
    private readonly string _thumbprint;
    private readonly IDpopThumbprintComputer _thumbprintComputer;
    private readonly TimeProvider _timeProvider;
    private readonly Mock<IDpopProofValidator> _validatorMock;

    public DpopValidationMiddlewareTests()
    {
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _securityKey = new ECDsaSecurityKey(_ecdsa) { KeyId = TestKeyId };

        var parameters = _ecdsa.ExportParameters(false);
        _publicJwk = new Dictionary<string, string>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(parameters.Q.X ??
                                            throw new InvalidOperationException("Failed to export X coordinate.")),
            ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y ??
                                            throw new InvalidOperationException("Failed to export Y coordinate.")),
            ["kid"] = TestKeyId
        };

        using var doc =
            JsonDocument.Parse(JsonSerializer.Serialize(_publicJwk, DpopJsonContext.Default.DictionaryStringString));
        _thumbprint = new DpopThumbprintComputer().Compute(doc.RootElement);

        _validatorMock = new Mock<IDpopProofValidator>(MockBehavior.Strict);
        _nonceStoreMock = new Mock<IDpopNonceStore>(MockBehavior.Strict);
        _thumbprintComputer = new DpopThumbprintComputer();
        _timeProvider = TimeProvider.System;
        _l1Cache = new L1AntiFloodCache(_timeProvider, TimeSpan.FromSeconds(3));

        _dpopOptions = Microsoft.Extensions.Options.Options.Create(new DPoPOptions
        {
            AllowedAlgorithms = ["ES256", "PS256"]
        });

        _logger = NullLogger<DpopValidationMiddleware>.Instance;

        var services = new ServiceCollection();
        services.AddSingleton(_logger);
        services.AddSingleton<IMlDsaSignatureVerifier>(new FailClosedMlDsaVerifier());
        services.AddSingleton<PqcCryptoProviderFactory>();
        _serviceProvider = services.BuildServiceProvider();
    }

    public void Dispose() => _ecdsa.Dispose();

    [Fact(DisplayName = "✅ InvokeAsync: With valid proof and nonce consumes and rotates successfully")]
    public async Task InvokeAsync_WithValidProofAndNonce_ConsumesAndRotatesSuccessfully()
    {
        // Arrange
        const string expectedNonce = "active-nonce-123";
        const string newNonce = "rotated-nonce-456";

        var dpopProof = CreateValidDpopProof("POST", TargetUrl, expectedNonce);
        var context = CreateHttpContextWithHeaders("DPoP access-token-abc", dpopProof);

        var responseFeature = new FakeHttpResponseFeature();
        context.Features.Set<IHttpResponseFeature>(responseFeature);

        _nonceStoreMock
            .Setup(x => x.GetNonceAsync(_thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedNonce);

        _validatorMock
            .Setup(x => x.ValidateAsync(It.IsAny<DpopValidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SecurityResultFactory.Create(new DpopValidationSuccess(newNonce, _thumbprint)));

        _nonceStoreMock
            .Setup(x => x.ConsumeNonceIfMatchesAsync(_thumbprint, expectedNonce, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        _nonceStoreMock
            .Setup(x => x.SetNonceAsync(_thumbprint, newNonce, It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Corrected: Mark as static and avoid closures by using the parameter context
        static Task Next(HttpContext httpContext)
        {
            httpContext.Response.StatusCode = StatusCodes.Status200OK;
            return Task.CompletedTask;
        }

        var middleware =
            new DpopValidationMiddleware(Next, _thumbprintComputer, _timeProvider, _l1Cache, _logger, _dpopOptions);

        // Act
        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object);
        await responseFeature.FireOnStartingAsync();

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);

        _nonceStoreMock.Verify(
            x => x.ConsumeNonceIfMatchesAsync(_thumbprint, expectedNonce, It.IsAny<CancellationToken>()), Times.Once);
        _nonceStoreMock.Verify(
            x => x.SetNonceAsync(_thumbprint, newNonce, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.Once);

        context.Response.Headers.Should().ContainKey("DPoP-Nonce");
        context.Response.Headers["DPoP-Nonce"].ToString().Should().Be(newNonce);
    }

    [Fact(DisplayName = "❌ InvokeAsync: Replayed nonce must fail before executing any business logic")]
    public async Task InvokeAsync_WithReplayedNonce_FailsBeforeExecutingBusinessLogic()
    {
        // Arrange
        const string expectedNonce = "already-consumed-nonce";

        var dpopProof = CreateValidDpopProof("POST", TargetUrl, expectedNonce);
        var context = CreateHttpContextWithHeaders("DPoP access-token-abc", dpopProof);

        _nonceStoreMock
            .Setup(x => x.GetNonceAsync(_thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedNonce);

        _validatorMock
            .Setup(x => x.ValidateAsync(It.IsAny<DpopValidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SecurityResultFactory.Create(new DpopValidationSuccess("any-nonce", _thumbprint)));

        _nonceStoreMock
            .Setup(x => x.ConsumeNonceIfMatchesAsync(_thumbprint, expectedNonce, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        // Corrected: Make static to satisfy performance analyzer guidelines
        static Task Next(HttpContext _)
        {
            throw new InvalidOperationException("Downstream pipeline should never execute.");
        }

        var middleware =
            new DpopValidationMiddleware(Next, _thumbprintComputer, _timeProvider, _l1Cache, _logger, _dpopOptions);

        // Act
        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        context.Response.Headers.WWWAuthenticate.ToString().Should().Contain("error=\"use_dpop_nonce\"");
    }

    [Fact(DisplayName = "❌ InvokeAsync: Request with symmetric key in header fails immediately")]
    public async Task InvokeAsync_WithSymmetricKeyInHeader_FailsImmediately()
    {
        // Arrange
        var symmetricKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("super-secret-key-32-bytes-long!!!"));
        var header = new Dictionary<string, object>
        {
            ["typ"] = "dpop+jwt",
            ["jwk"] = new Dictionary<string, string>
            {
                ["kty"] = "oct",
                ["k"] = Base64UrlEncoder.Encode(symmetricKey.Key)
            }
        };
        var payload = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = "POST",
            ["htu"] = TargetUrl,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        var dpopProof = CreateSymmetricToken(symmetricKey, "HS256", header, payload);
        var context = CreateHttpContextWithHeaders("DPoP access-token-abc", dpopProof);

        static Task Next(HttpContext _)
        {
            throw new InvalidOperationException("Bypass detected.");
        }

        var middleware =
            new DpopValidationMiddleware(Next, _thumbprintComputer, _timeProvider, _l1Cache, _logger, _dpopOptions);

        // Act
        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        context.Response.Headers.WWWAuthenticate.ToString().Should().Contain("invalid_dpop_proof");
    }

    [Fact(DisplayName = "🛡️ Resiliency: Aborted request during OnStarting must be handled safely")]
    public async Task InvokeAsync_WhenRequestAbortedDuringOnStarting_HandlesExceptionSafely()
    {
        // Arrange
        const string expectedNonce = "active-nonce-777";
        const string newNonce = "new-nonce-888";
        var dpopProof = CreateValidDpopProof("GET", TargetUrl, expectedNonce);
        var context = CreateHttpContextWithHeaders("DPoP token", dpopProof);

        var responseFeature = new FakeHttpResponseFeature();
        context.Features.Set<IHttpResponseFeature>(responseFeature);

        _nonceStoreMock.Setup(x => x.GetNonceAsync(_thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedNonce);
        _nonceStoreMock
            .Setup(x => x.ConsumeNonceIfMatchesAsync(_thumbprint, expectedNonce, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        _validatorMock
            .Setup(x => x.ValidateAsync(It.IsAny<DpopValidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SecurityResultFactory.Create(new DpopValidationSuccess(newNonce, _thumbprint)));

        _nonceStoreMock
            .Setup(x => x.SetNonceAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());

        static Task Next(HttpContext httpContext)
        {
            httpContext.Response.StatusCode = StatusCodes.Status200OK;
            return Task.CompletedTask;
        }

        var middleware =
            new DpopValidationMiddleware(Next, _thumbprintComputer, _timeProvider, _l1Cache, _logger, _dpopOptions);

        // Act
        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object);
        var act = async () => await responseFeature.FireOnStartingAsync();

        // Assert
        await act.Should().NotThrowAsync<OperationCanceledException>();
    }

    [Fact(DisplayName = "🛡️ Resiliency: Database crashes during OnStarting must throw to allow pipeline failure")]
    public async Task InvokeAsync_WhenDatabaseCrashesDuringOnStarting_ThrowsException()
    {
        // Arrange
        const string expectedNonce = "active-nonce-777";
        const string newNonce = "new-nonce-888";
        var dpopProof = CreateValidDpopProof("GET", TargetUrl, expectedNonce);
        var context = CreateHttpContextWithHeaders("DPoP token", dpopProof);

        var responseFeature = new FakeHttpResponseFeature();
        context.Features.Set<IHttpResponseFeature>(responseFeature);

        _nonceStoreMock
            .Setup(x => x.ConsumeNonceIfMatchesAsync(_thumbprint, expectedNonce, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        _validatorMock
            .Setup(x => x.ValidateAsync(It.IsAny<DpopValidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SecurityResultFactory.Create(new DpopValidationSuccess(newNonce, _thumbprint)));

        _nonceStoreMock
            .Setup(x => x.SetNonceAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("PostgreSQL cluster unavailable"));

        _nonceStoreMock
            .SetupSequence(x => x.GetNonceAsync(_thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedNonce)
            .ThrowsAsync(new InvalidOperationException("PostgreSQL cluster unavailable"));

        static Task Next(HttpContext httpContext)
        {
            httpContext.Response.StatusCode = StatusCodes.Status200OK;
            return Task.CompletedTask;
        }

        var middleware =
            new DpopValidationMiddleware(Next, _thumbprintComputer, _timeProvider, _l1Cache, _logger, _dpopOptions);

        // Act
        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object);
        var act = async () => await responseFeature.FireOnStartingAsync();

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("PostgreSQL cluster unavailable");
    }

    [Fact(DisplayName =
        "🛡️ Resiliency: Client cancellation during timing-floor delay exits cleanly without throwing unhandled exceptions")]
    public async Task InvokeAsync_WhenRequestCancelledDuringTimingDelay_ExitsGracefully()
    {
        // Arrange
        using var cts = new CancellationTokenSource();
        var context = CreateHttpContextWithHeaders("DPoP access-token-abc", "invalid.dpop.proof.token");
        context.RequestAborted = cts.Token;

        await cts.CancelAsync();

        static Task Next(HttpContext _)
        {
            throw new InvalidOperationException("Pipeline should not proceed under cancelled requests.");
        }

        var middleware =
            new DpopValidationMiddleware(Next, _thumbprintComputer, _timeProvider, _l1Cache, _logger, _dpopOptions);

        // Act
        var act = async () => await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object);

        // Assert
        await act.Should().NotThrowAsync();
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Fact(DisplayName =
        "🛡️ Resiliency: Exception shielding handles OperationCanceledException and IOException during response write")]
    public async Task InvokeAsync_WhenWriteThrowsCancellationOrSocketError_IsShielded()
    {
        // Arrange
        var context = CreateHttpContextWithHeaders("DPoP access-token-abc", "invalid.dpop.proof.token");

        var throwingStream = new Mock<Stream>();
        throwingStream
            .Setup(s => s.WriteAsync(It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException("Socket closed by peer."));

        context.Response.Body = throwingStream.Object;

        static Task Next(HttpContext _)
        {
            return Task.CompletedTask;
        }

        var middleware =
            new DpopValidationMiddleware(Next, _thumbprintComputer, _timeProvider, _l1Cache, _logger, _dpopOptions);

        // Act
        var act = async () => await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object);

        // Assert
        await act.Should().NotThrowAsync();
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

    private static string CreateSymmetricToken(SymmetricSecurityKey key, string algorithm,
        Dictionary<string, object> header, Dictionary<string, object> payload)
    {
        var jwtHandler = new JsonWebTokenHandler();
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = payload,
            SigningCredentials = new SigningCredentials(key, algorithm),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims =
                new Dictionary<string, object>()
        };

        foreach (var h in header)
        {
            descriptor.AdditionalHeaderClaims[h.Key] = h.Value;
        }

        return jwtHandler.CreateToken(descriptor);
    }

    private DefaultHttpContext CreateHttpContextWithHeaders(string authHeader, string dpopHeader)
    {
        var context = new DefaultHttpContext { RequestServices = _serviceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString(TargetHost);
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

    private sealed class FakeHttpResponseFeature : IHttpResponseFeature
    {
        private readonly List<(Func<object, Task> Callback, object State)> _callbacks = [];

        public int StatusCode { get; set; } = 200;
        public string? ReasonPhrase { get; set; }
        public IHeaderDictionary Headers { get; set; } = new HeaderDictionary();
        public Stream Body { get; set; } = new MemoryStream();
        public bool HasStarted => false;

        public void OnStarting(Func<object, Task> callback, object state) => _callbacks.Add((callback, state));

        public void OnCompleted(Func<object, Task> callback, object state)
        {
        }

        public async Task FireOnStartingAsync()
        {
            foreach (var (callback, state) in _callbacks)
            {
                await callback(state);
            }
        }
    }
}
