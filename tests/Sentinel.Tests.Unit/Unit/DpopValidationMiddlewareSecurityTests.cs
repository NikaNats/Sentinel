using System.Security.Cryptography;
using System.Text;
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
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Pqc;
using Sentinel.Security.Abstractions.Results;

namespace Sentinel.Tests.Unit.Unit;

public sealed class DpopValidationMiddlewareSecurityTests
{
    private readonly IOptions<DPoPOptions> _dpopOptions;
    private readonly L1AntiFloodCache _l1Cache;
    private readonly Mock<IDpopNonceStore> _nonceStoreMock;
    private readonly IServiceProvider _serviceProvider;
    private readonly IDpopThumbprintComputer _thumbprintComputer;
    private readonly TimeProvider _timeProvider;
    private readonly Mock<IDpopProofValidator> _validatorMock;

    public DpopValidationMiddlewareSecurityTests()
    {
        _validatorMock = new Mock<IDpopProofValidator>(MockBehavior.Strict);
        _nonceStoreMock = new Mock<IDpopNonceStore>(MockBehavior.Strict);
        _thumbprintComputer = new DpopThumbprintComputer();
        _timeProvider = TimeProvider.System;
        _l1Cache = new L1AntiFloodCache(_timeProvider, TimeSpan.FromSeconds(3));

        var options = new DPoPOptions
        {
            AllowedAlgorithms = ["ES256", "PS256", "ML-DSA-65"]
        };
        _dpopOptions = Microsoft.Extensions.Options.Options.Create(options);

        var services = new ServiceCollection();
        services.AddSingleton<ILogger<DpopValidationMiddleware>>(NullLogger<DpopValidationMiddleware>.Instance);
        services.AddSingleton<IMlDsaSignatureVerifier>(new FailClosedMlDsaVerifier());
        services.AddSingleton<PqcCryptoProviderFactory>();
        _serviceProvider = services.BuildServiceProvider();
    }

    [Fact(DisplayName = "🔐 Security: Middleware rejects symmetric HS256 algorithm instantly")]
    public async Task InvokeAsync_WithSymmetricAlgorithm_Returns401()
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
        var context = CreateHttpContextWithHeaders("DPoP access-token", dpopProof);

        RequestDelegate next = _ => throw new InvalidOperationException("Pipeline bypass detected!");
        var middleware = new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache,
            NullLogger<DpopValidationMiddleware>.Instance, _dpopOptions);

        // Act
        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        context.Response.Headers.WWWAuthenticate.ToString().Should().Contain("invalid_dpop_proof");
    }

    [Fact(DisplayName = "🔐 Security: Middleware rejects JWK with symmetric kty 'oct'")]
    public async Task InvokeAsync_WithSymmetricKty_Returns401()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new ECDsaSecurityKey(ecdsa);

        var header = new Dictionary<string, object>
        {
            ["typ"] = "dpop+jwt",
            ["jwk"] = new Dictionary<string, string>
            {
                ["kty"] = "oct",
                ["k"] = Base64UrlEncoder.Encode(new byte[32])
            }
        };
        var payload = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = "POST",
            ["htu"] = "https://api.sentinel.io/resource",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        var dpopProof = CreateAsymmetricToken(key, SecurityAlgorithms.EcdsaSha256, header, payload);
        var context = CreateHttpContextWithHeaders("DPoP access-token", dpopProof);

        RequestDelegate next = _ => throw new InvalidOperationException("Pipeline bypass detected!");
        var middleware = new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache,
            NullLogger<DpopValidationMiddleware>.Instance, _dpopOptions);

        // Act
        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Fact(DisplayName = "🔐 Security: Middleware rejects JWK containing private key material 'd'")]
    public async Task InvokeAsync_WithPrivateKeyInJwk_Returns401()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new ECDsaSecurityKey(ecdsa);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);

        var header = new Dictionary<string, object>
        {
            ["typ"] = "dpop+jwt",
            ["jwk"] = new Dictionary<string, object>
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["x"] = jwk.X!,
                ["y"] = jwk.Y!,
                ["d"] = Base64UrlEncoder.Encode(new byte[32])
            }
        };
        var payload = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = "POST",
            ["htu"] = "https://api.sentinel.io/resource",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        var dpopProof = CreateAsymmetricToken(key, SecurityAlgorithms.EcdsaSha256, header, payload);
        var context = CreateHttpContextWithHeaders("DPoP access-token", dpopProof);

        RequestDelegate next = _ => throw new InvalidOperationException("Pipeline bypass detected!");
        var middleware = new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache,
            NullLogger<DpopValidationMiddleware>.Instance, _dpopOptions);

        // Act
        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Fact(DisplayName = "🛡️ DoS Defense: Bypassed signature validation instantly when thumbprint is L1 Blacklisted")]
    public async Task InvokeAsync_WhenL1Blacklisted_FailsClosedInstantly()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new ECDsaSecurityKey(ecdsa);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);

        var header = new Dictionary<string, object>
        {
            ["typ"] = "dpop+jwt",
            ["jwk"] = new Dictionary<string, object>
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["x"] = jwk.X!,
                ["y"] = jwk.Y!
            }
        };
        var payload = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = "POST",
            ["htu"] = "https://api.sentinel.io/resource",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        var dpopProof = CreateAsymmetricToken(key, SecurityAlgorithms.EcdsaSha256, header, payload);
        var context = CreateHttpContextWithHeaders("DPoP access-token", dpopProof);

        using var jwkDoc = JsonDocument.Parse(JsonSerializer.Serialize(header["jwk"]));
        var thumbprint = _thumbprintComputer.Compute(jwkDoc.RootElement);
        _l1Cache.RecordFailedAttempt(thumbprint);

        RequestDelegate next = _ => throw new InvalidOperationException("Pipeline bypass detected!");
        var middleware = new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache,
            NullLogger<DpopValidationMiddleware>.Instance, _dpopOptions);

        // Act & Assert
        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object);

        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        context.Response.Headers.WWWAuthenticate.ToString().Should().Contain("invalid_dpop_proof");
    }

    [Fact(DisplayName = "🛡️ Security: Bearer Token on DPoP-protected endpoint is rejected as Downgrade Attempt")]
    public async Task InvokeAsync_WithBearerToken_TriggersConstantTimeFailure()
    {
        var context = CreateHttpContextWithHeaders("Bearer raw-bearer-token-value", string.Empty);

        RequestDelegate next = _ => throw new InvalidOperationException("Bypass allowed!");
        var middleware = new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache,
            NullLogger<DpopValidationMiddleware>.Instance, _dpopOptions);

        // Act
        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        context.Response.Headers.WWWAuthenticate.ToString().Should().Contain("error=\"invalid_dpop_proof\"");
    }

    [Fact(DisplayName =
        "🛡️ Concurrency: When nonce atomic consumption fails (TOCTOU), issues new rotated challenge nonce")]
    public async Task InvokeAsync_WhenNonceConsumptionFails_IssuesNewChallengeNonce()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new ECDsaSecurityKey(ecdsa);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);

        var header = new Dictionary<string, object>
        {
            ["typ"] = "dpop+jwt",
            ["jwk"] = new Dictionary<string, object>
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["x"] = jwk.X!,
                ["y"] = jwk.Y!
            }
        };
        var payload = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = "POST",
            ["htu"] = "https://api.sentinel.io/resource",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        var dpopProof = CreateAsymmetricToken(key, SecurityAlgorithms.EcdsaSha256, header, payload);
        var context = CreateHttpContextWithHeaders("DPoP access-token", dpopProof);

        using var jwkDoc = JsonDocument.Parse(JsonSerializer.Serialize(header["jwk"]));
        var thumbprint = _thumbprintComputer.Compute(jwkDoc.RootElement);

        _nonceStoreMock
            .Setup(x => x.GetNonceAsync(thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync("stale-nonce-value");

        var validationSuccess = new DpopValidationSuccess("new-rotated-nonce", thumbprint);
        _validatorMock
            .Setup(x => x.ValidateAsync(It.IsAny<DpopValidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SecurityResultFactory.Create(validationSuccess));

        _nonceStoreMock
            .Setup(x => x.ConsumeNonceIfMatchesAsync(thumbprint, "stale-nonce-value", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        // Corrected: Set up the underlying interface method SetNonceAsync instead of TryStoreNonceAsync
        _nonceStoreMock
            .Setup(x => x.SetNonceAsync(thumbprint, It.IsAny<string>(), It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        RequestDelegate next = _ => Task.CompletedTask;
        var middleware = new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache,
            NullLogger<DpopValidationMiddleware>.Instance, _dpopOptions);

        // Act
        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        context.Response.Headers.Should().ContainKey("DPoP-Nonce");
        context.Response.Headers.WWWAuthenticate.ToString().Should().Contain("error=\"use_dpop_nonce\"");
    }

    private static string CreateSymmetricToken(SymmetricSecurityKey key, string algorithm,
        Dictionary<string, object> header, Dictionary<string, object> payload)
    {
        var handler = new JsonWebTokenHandler();
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

        return handler.CreateToken(descriptor);
    }

    private static string CreateAsymmetricToken(AsymmetricSecurityKey key, string algorithm,
        Dictionary<string, object> header, Dictionary<string, object> payload)
    {
        var handler = new JsonWebTokenHandler();
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

        return handler.CreateToken(descriptor);
    }

    private DefaultHttpContext CreateHttpContextWithHeaders(string authHeader, string dpopHeader)
    {
        var context = new DefaultHttpContext { RequestServices = _serviceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("api.sentinel.io");
        context.Request.Path = "/resource";
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
