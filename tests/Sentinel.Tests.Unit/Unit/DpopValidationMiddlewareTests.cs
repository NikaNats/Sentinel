using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Sentinel.AspNetCore.Middleware;
using Sentinel.AspNetCore.Stores;
using Sentinel.DPoP;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Results;

namespace Sentinel.Tests.Unit.Unit;

public sealed class DpopValidationMiddlewareTests : IDisposable
{
    private const string TestKeyId = "test-key-2026";
    private readonly IOptions<DPoPOptions> _dpopOptions;
    private readonly ECDsa _ecdsa;
    private readonly L1AntiFloodCache _l1Cache;
    private readonly Mock<IDpopNonceStore> _nonceStoreMock;
    private readonly Dictionary<string, string> _publicJvh;
    private readonly ECDsaSecurityKey _securityKey;
    private readonly string _thumbprint;
    private readonly IDpopThumbprintComputer _thumbprintComputer;
    private readonly TimeProvider _timeProvider;

    private readonly Mock<IDpopProofValidator> _validatorMock;

    public DpopValidationMiddlewareTests()
    {
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _securityKey = new ECDsaSecurityKey(_ecdsa) { KeyId = TestKeyId };

        var parameters = _ecdsa.ExportParameters(false);
        _publicJvh = new Dictionary<string, string>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(parameters.Q.X ?? throw new InvalidOperationException()),
            ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y ?? throw new InvalidOperationException()),
            ["kid"] = TestKeyId
        };

        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(_publicJvh));
        _thumbprint = new DpopThumbprintComputer().Compute(doc.RootElement);

        _validatorMock = new Mock<IDpopProofValidator>(MockBehavior.Strict);
        _nonceStoreMock = new Mock<IDpopNonceStore>(MockBehavior.Strict);
        _thumbprintComputer = new DpopThumbprintComputer();
        _timeProvider = TimeProvider.System;
        _l1Cache = new L1AntiFloodCache(_timeProvider, TimeSpan.FromSeconds(3));

        var options = new DPoPOptions();
        options.AllowedAlgorithms.Clear();
        options.AllowedAlgorithms.Add("ES256");
        options.AllowedAlgorithms.Add("PS256");
        _dpopOptions = Microsoft.Extensions.Options.Options.Create(options);
    }

    public void Dispose() => _ecdsa.Dispose();

    [Fact]
    public async Task InvokeAsync_WithValidProofAndNonce_ConsumesAndRotatesSuccessfully()
    {
        const string expectedNonce = "active-nonce-123";
        const string newNonce = "rotated-nonce-456";
        const string targetUri = "https://api.sentinel.io/resource";

        var dpopProof = CreateValidDpopProof("POST", targetUri, expectedNonce);
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
            .ReturnsAsync(true)
            .Verifiable();

        _nonceStoreMock
            .Setup(x => x.SetNonceAsync(_thumbprint, newNonce, It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask)
            .Verifiable();

        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            context.Response.StatusCode = 200;
            return Task.CompletedTask;
        };

        var middleware = new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache, null);

        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object, _dpopOptions);
        await responseFeature.FireOnStartingAsync();

        nextCalled.Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);

        _nonceStoreMock.Verify(
            x => x.ConsumeNonceIfMatchesAsync(_thumbprint, expectedNonce, It.IsAny<CancellationToken>()), Times.Once);
        _nonceStoreMock.Verify(
            x => x.SetNonceAsync(_thumbprint, newNonce, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.Once);

        context.Response.Headers.Should().ContainKey("DPoP-Nonce");
        context.Response.Headers["DPoP-Nonce"].ToString().Should().Be(newNonce);
    }

    [Fact]
    public async Task InvokeAsync_WithReplayedNonce_FailsBeforeExecutingBusinessLogic()
    {
        const string expectedNonce = "already-consumed-nonce";
        const string targetUri = "https://api.sentinel.io/resource";

        var dpopProof = CreateValidDpopProof("POST", targetUri, expectedNonce);
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

        RequestDelegate next = _ => throw new InvalidOperationException();
        var middleware = new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache, null);

        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object, _dpopOptions);

        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        context.Response.Headers.WWWAuthenticate.ToString().Should().Contain("error=\"use_dpop_nonce\"");
    }

    [Fact]
    public async Task InvokeAsync_WhenRequestAbortedDuringOnStarting_HandlesExceptionSafely()
    {
        const string expectedNonce = "active-nonce-777";
        const string newNonce = "new-nonce-888";
        var dpopProof = CreateValidDpopProof("GET", "https://api.sentinel.io/resource", expectedNonce);
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

        RequestDelegate next = _ =>
        {
            context.Response.StatusCode = 200;
            return Task.CompletedTask;
        };
        var middleware = new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache, null);

        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object, _dpopOptions);

        var act = async () => await responseFeature.FireOnStartingAsync();
        await act.Should().NotThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task InvokeAsync_WhenDatabaseCrashesDuringOnStarting_ThrowsException()
    {
        const string expectedNonce = "active-nonce-777";
        const string newNonce = "new-nonce-888";
        var dpopProof = CreateValidDpopProof("GET", "https://api.sentinel.io/resource", expectedNonce);
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

        RequestDelegate next = _ =>
        {
            context.Response.StatusCode = 200;
            return Task.CompletedTask;
        };
        var middleware = new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache, null);

        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object, _dpopOptions);

        var act = async () => await responseFeature.FireOnStartingAsync();
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("PostgreSQL cluster unavailable");
    }

    [Fact]
    public async Task InvokeAsync_WithSymmetricKeyInHeader_FailsImmediately()
    {
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
            ["htu"] = "https://api.sentinel.io/resource",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        var dpopProof = CreateSymmetricToken(symmetricKey, "HS256", header, payload);
        var context = CreateHttpContextWithHeaders("DPoP access-token-abc", dpopProof);

        RequestDelegate next = _ => Task.CompletedTask;
        var middleware = new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache, null);

        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object, _dpopOptions);

        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        context.Response.Headers.WWWAuthenticate.ToString().Should().Contain("invalid_dpop_proof");
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
            TokenType = "dpop+jwt"
        };

        descriptor.AdditionalHeaderClaims = new Dictionary<string, object>
        {
            ["jwk"] = _publicJvh
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
            AdditionalHeaderClaims = new Dictionary<string, object>()
        };

        foreach (var h in header)
        {
            descriptor.AdditionalHeaderClaims[h.Key] = h.Value;
        }

        return jwtHandler.CreateToken(descriptor);
    }

    private static DefaultHttpContext CreateHttpContextWithHeaders(string authHeader, string dpopHeader)
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("api.sentinel.io");
        context.Request.Path = "/resource";
        context.Request.Method = HttpMethods.Post;
        context.Request.Headers.Authorization = authHeader;
        context.Request.Headers["DPoP"] = dpopHeader;
        context.Response.Body = new MemoryStream();

        var services = new ServiceCollection();
        services.AddLogging();
        context.RequestServices = services.BuildServiceProvider();

        return context;
    }

    private sealed class FakeHttpResponseFeature : IHttpResponseFeature
    {
        private readonly List<(Func<object, Task> Callback, object State)> _callbacks = new();

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
