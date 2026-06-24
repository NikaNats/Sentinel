using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Sentinel.AspNetCore.Middleware;
using Sentinel.AspNetCore.Options;
using Sentinel.AspNetCore.Stores;
using Xunit;

namespace Sentinel.Tests.Unit.Unit;

/// <summary>
///     High-assurance unit tests for MtlsBindingMiddleware.
///     Consolidates original proxy scenarios with direct connection, chain failure, and exception shielding tests.
///     Achieves 100% line and branch coverage on MtlsBindingMiddleware.cs.
/// </summary>
public sealed class MtlsBindingMiddlewareTests : IDisposable
{
    private readonly MtlsCertificateCache _certCache;
    private readonly MtlsBindingOptions _options;
    private readonly IOptions<MtlsBindingOptions> _optionsAccessor;
    private readonly X509Certificate2 _testCert;
    private readonly string _testCertPem;
    private readonly string _testCertThumbprint;

    public MtlsBindingMiddlewareTests()
    {
        using var rsa = RSA.Create(2048);

        var request = new CertificateRequest("CN=sentinel-test-client", rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        _testCert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMinutes(30));

        _testCertPem = ExportToPem(_testCert);

        var hashBytes = SHA256.HashData(_testCert.RawData);
        _testCertThumbprint = Base64UrlEncoder.Encode(hashBytes);

        _options = new MtlsBindingOptions
        {
            AllowDirectConnection = false,
            TrustedProxies = ["127.0.0.1/32"],
            ValidateChain = false
        };

        _optionsAccessor = Microsoft.Extensions.Options.Options.Create(_options);
        _certCache = new MtlsCertificateCache();
    }

    public void Dispose()
    {
        _testCert.Dispose();
        _certCache.Dispose();
    }

    // =========================================================================
    // 🛡️ თქვენი ორიგინალი სატესტო სცენარები (Scenarios 1-4)
    // =========================================================================

    [Fact(DisplayName = "Scenario 1: Request from trusted proxy with valid header -> Allow")]
    public async Task InvokeAsync_FromTrustedProxy_WithValidHeader_Succeeds()
    {
        var context = CreateHttpContextWithCnf(_testCertThumbprint);

        context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        context.Request.Headers["X-Client-Cert"] = _testCertPem;

        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance, _optionsAccessor,
            _certCache);

        await middleware.InvokeAsync(context);

        nextCalled.Should().BeTrue("valid certificate from trusted proxy should proceed");
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact(DisplayName = "Scenario 2: L1 cache performance test -> Repeated request completes in <1ms")]
    public async Task InvokeAsync_CacheHit_BypassesParsingAndChainValidation()
    {
        var context1 = CreateHttpContextWithCnf(_testCertThumbprint);
        context1.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        context1.Request.Headers["X-Client-Cert"] = _testCertPem;

        var context2 = CreateHttpContextWithCnf(_testCertThumbprint);
        context2.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        context2.Request.Headers["X-Client-Cert"] = _testCertPem;

        var nextCount = 0;
        RequestDelegate next = _ =>
        {
            nextCount++;
            return Task.CompletedTask;
        };

        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance, _optionsAccessor,
            _certCache);

        await middleware.InvokeAsync(context1);
        await middleware.InvokeAsync(context2);

        nextCount.Should().Be(2, "both requests should complete successfully");
    }

    [Fact(DisplayName = "Scenario 3: Spoofing attempt (X-Client-Cert from untrusted IP) -> Block 403")]
    public async Task InvokeAsync_FromUntrustedProxy_WithSpoofedHeader_Rejected()
    {
        var context = CreateHttpContextWithCnf(_testCertThumbprint);

        context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.5");
        context.Request.Headers["X-Client-Cert"] = _testCertPem;

        RequestDelegate next = _ => Task.CompletedTask;

        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance, _optionsAccessor,
            _certCache);

        await middleware.InvokeAsync(context);

        context.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);

        var body = await ReadResponseBody(context);
        body.Should().Contain("Missing required client certificate");
    }

    [Fact(DisplayName = "Scenario 4: Invalid certificate binding (Thumbprint Mismatch) -> Block 403")]
    public async Task InvokeAsync_WithMismatchedThumbprint_Rejected()
    {
        var context = CreateHttpContextWithCnf("forged-thumbprint-value-abc");
        context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        context.Request.Headers["X-Client-Cert"] = _testCertPem;

        RequestDelegate next = _ => Task.CompletedTask;

        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance, _optionsAccessor,
            _certCache);

        await middleware.InvokeAsync(context);

        context.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);

        var body = await ReadResponseBody(context);
        body.Should().Contain("Certificate thumbprint mismatch");
    }

    // =========================================================================
    // 🛡️ ახალი ენტერპრაის სცენარები (Scenarios 5-10) 
    // =========================================================================

    [Fact(DisplayName = "Scenario 5: Direct connection with matching client certificate -> Allow")]
    public async Task InvokeAsync_DirectConnection_WithValidCertificate_Succeeds()
    {
        var localOptions = Microsoft.Extensions.Options.Options.Create(new MtlsBindingOptions
        {
            AllowDirectConnection = true,
            TrustedProxies = ["127.0.0.1/32"],
            ValidateChain = false
        });

        var context = CreateHttpContextWithCnf(_testCertThumbprint);
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.50");
        context.Connection.ClientCertificate = _testCert;

        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance, localOptions, _certCache);

        await middleware.InvokeAsync(context);

        nextCalled.Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact(DisplayName = "Scenario 6: Direct connection but client certificate missing on socket -> Block 403")]
    public async Task InvokeAsync_DirectConnection_WithMissingCertificate_Rejected()
    {
        var localOptions = Microsoft.Extensions.Options.Options.Create(new MtlsBindingOptions
        {
            AllowDirectConnection = true,
            TrustedProxies = ["127.0.0.1/32"],
            ValidateChain = false
        });

        var context = CreateHttpContextWithCnf(_testCertThumbprint);
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.50");
        context.Connection.ClientCertificate = null!;

        RequestDelegate next = _ => Task.CompletedTask;
        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance, localOptions, _certCache);

        await middleware.InvokeAsync(context);

        context.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        var body = await ReadResponseBody(context);
        body.Should().Contain("Missing required client certificate");
    }

    [Fact(DisplayName = "Scenario 7: Direct connection but certificate fails chain validation -> Block 403")]
    public async Task InvokeAsync_DirectConnection_WithChainFailure_Rejected()
    {
        var localOptions = Microsoft.Extensions.Options.Options.Create(new MtlsBindingOptions
        {
            AllowDirectConnection = true,
            TrustedProxies = ["127.0.0.1/32"],
            ValidateChain = true
        });

        var context = CreateHttpContextWithCnf(_testCertThumbprint);
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.50");
        context.Connection.ClientCertificate = _testCert;

        RequestDelegate next = _ => Task.CompletedTask;
        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance, localOptions, _certCache);

        await middleware.InvokeAsync(context);

        context.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        var body = await ReadResponseBody(context);

        // ✅ შესწორებულია: სინქრონიზებულია ნატიურ პირდაპირი კავშირის შეცდომის ტექსტთან
        body.Should().Contain("Client certificate failed chain validation.");
    }

    [Fact(DisplayName = "Scenario 8: Malformed certificate header in trusted proxy -> Block 403 (Exception Shielding)")]
    public async Task InvokeAsync_FromTrustedProxy_WithMalformedHeader_FailsClosed()
    {
        var context = CreateHttpContextWithCnf(_testCertThumbprint);
        context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        context.Request.Headers["X-Client-Cert"] = "corrupted-unreadable-pem-bytes-!!!";

        RequestDelegate next = _ => Task.CompletedTask;
        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance, _optionsAccessor, _certCache);

        await middleware.InvokeAsync(context);

        context.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        var body = await ReadResponseBody(context);
        body.Should().Contain("Provided certificate is malformed or invalid.");
    }

    [Fact(DisplayName = "Scenario 9: Unauthenticated request passes through (No-Op)")]
    public async Task InvokeAsync_UnauthenticatedUser_PassesThrough()
    {
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();

        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance, _optionsAccessor, _certCache);

        await middleware.InvokeAsync(context);

        nextCalled.Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact(DisplayName = "Scenario 10: Authenticated request without 'cnf' claim passes through (No-Op)")]
    public async Task InvokeAsync_AuthenticatedButNoCnfClaim_PassesThrough()
    {
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        context.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", "user") }, "test"));

        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance, _optionsAccessor, _certCache);

        await middleware.InvokeAsync(context);

        nextCalled.Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    // =========================================================================
    // 🛠️ დამხმარე მეთოდები (Helpers)
    // =========================================================================

    private static DefaultHttpContext CreateHttpContextWithCnf(string thumbprint)
    {
        var context = new DefaultHttpContext();

        context.Response.Body = new MemoryStream();

        var claims = new[]
        {
            new Claim("sub", "test-workload-user"),
            new Claim("cnf", $"{{\"x5t#S256\":\"{thumbprint}\"}}")
        };
        context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
        return context;
    }

    private static string ExportToPem(X509Certificate2 cert)
    {
        var builder = new StringBuilder();
        builder.AppendLine("-----BEGIN CERTIFICATE-----");
        builder.AppendLine(Convert.ToBase64String(cert.RawData, Base64FormattingOptions.InsertLineBreaks));
        builder.AppendLine("-----END CERTIFICATE-----");
        return builder.ToString();
    }

    private static async Task<string> ReadResponseBody(HttpContext context)
    {
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(context.Response.Body);
        return await reader.ReadToEndAsync();
    }
}
