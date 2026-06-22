using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
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

namespace Sentinel.Tests.Unit.Unit;

public sealed class DpopValidationMiddlewareSecurityTests
{
    private readonly Mock<IDpopProofValidator> _validatorMock;
    private readonly Mock<IDpopNonceStore> _nonceStoreMock;
    private readonly IDpopThumbprintComputer _thumbprintComputer;
    private readonly TimeProvider _timeProvider;
    private readonly L1AntiFloodCache _l1Cache;
    private readonly IOptions<DPoPOptions> _dpopOptions;

    public DpopValidationMiddlewareSecurityTests()
    {
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

        RequestDelegate next = _ => throw new InvalidOperationException("Pipeline bypass detected! Downstream executed.");
        var middleware = new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache);

        // Act
        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object, _dpopOptions);

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

        RequestDelegate next = _ => throw new InvalidOperationException("Pipeline bypass detected! Downstream executed.");
        var middleware = new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache);

        // Act
        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object, _dpopOptions);

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
        var middleware = new DpopValidationMiddleware(next, _thumbprintComputer, _timeProvider, _l1Cache);

        // Act
        await middleware.InvokeAsync(context, _validatorMock.Object, _nonceStoreMock.Object, _dpopOptions);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    private static string CreateSymmetricToken(SymmetricSecurityKey key, string algorithm, Dictionary<string, object> header, Dictionary<string, object> payload)
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

    private static string CreateAsymmetricToken(AsymmetricSecurityKey key, string algorithm, Dictionary<string, object> header, Dictionary<string, object> payload)
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
        return context;
    }
}
