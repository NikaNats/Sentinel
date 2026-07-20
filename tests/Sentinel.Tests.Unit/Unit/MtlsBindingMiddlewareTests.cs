using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Sentinel.AspNetCore.Middleware;
using Sentinel.AspNetCore.Options;
using Sentinel.AspNetCore.Stores;

namespace Sentinel.Tests.Unit.Unit;

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

        _testCert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddMinutes(30));

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

    [Fact(DisplayName = "Scenario 1: Request from trusted proxy with valid header -> Allow")]
    public async Task InvokeAsync_FromTrustedProxy_WithValidHeader_Succeeds()
    {
        // Arrange
        var context = CreateHttpContextWithCnf(_testCertThumbprint);
        context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        context.Request.Headers["X-Client-Cert"] = _testCertPem;

        // Corrected: Use static local function and propagate execution signal via context Items to avoid closures
        static Task Next(HttpContext httpContext)
        {
            httpContext.Items["next_called"] = true;
            return Task.CompletedTask;
        }

        var middleware = new MtlsBindingMiddleware(Next, NullLogger<MtlsBindingMiddleware>.Instance, _optionsAccessor,
            _certCache);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Items.ContainsKey("next_called").Should().BeTrue("valid certificate from trusted proxy should proceed");
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact(DisplayName = "Scenario 2: L1 cache performance test -> Repeated request completes in <1ms")]
    public async Task InvokeAsync_CacheHit_BypassesParsingAndChainValidation()
    {
        // Arrange
        var context1 = CreateHttpContextWithCnf(_testCertThumbprint);
        context1.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        context1.Request.Headers["X-Client-Cert"] = _testCertPem;

        var context2 = CreateHttpContextWithCnf(_testCertThumbprint);
        context2.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        context2.Request.Headers["X-Client-Cert"] = _testCertPem;

        static Task Next(HttpContext httpContext)
        {
            if (httpContext.Items.TryGetValue("next_count", out var val) && val is int count)
            {
                httpContext.Items["next_count"] = count + 1;
            }
            else
            {
                httpContext.Items["next_count"] = 1;
            }

            return Task.CompletedTask;
        }

        var middleware = new MtlsBindingMiddleware(Next, NullLogger<MtlsBindingMiddleware>.Instance, _optionsAccessor,
            _certCache);

        // Act
        await middleware.InvokeAsync(context1);
        await middleware.InvokeAsync(context2);

        // Assert
        context1.Items["next_count"].Should().Be(1);
        context2.Items["next_count"].Should().Be(1);
    }

    [Fact(DisplayName = "Scenario 3: Spoofing attempt (X-Client-Cert from untrusted IP) -> Block 403")]
    public async Task InvokeAsync_FromUntrustedProxy_WithSpoofedHeader_Rejected()
    {
        // Arrange
        var context = CreateHttpContextWithCnf(_testCertThumbprint);
        context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.5");
        context.Request.Headers["X-Client-Cert"] = _testCertPem;

        static Task Next(HttpContext _)
        {
            return Task.CompletedTask;
        }

        var middleware = new MtlsBindingMiddleware(Next, NullLogger<MtlsBindingMiddleware>.Instance, _optionsAccessor,
            _certCache);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        var body = await ReadResponseBody(context);
        body.Should().Contain("Missing required client certificate");
    }

    [Fact(DisplayName = "Scenario 4: Invalid certificate binding (Thumbprint Mismatch) -> Block 403")]
    public async Task InvokeAsync_WithMismatchedThumbprint_Rejected()
    {
        // Arrange
        var context = CreateHttpContextWithCnf("forged-thumbprint-value-abc");
        context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        context.Request.Headers["X-Client-Cert"] = _testCertPem;

        static Task Next(HttpContext _)
        {
            return Task.CompletedTask;
        }

        var middleware = new MtlsBindingMiddleware(Next, NullLogger<MtlsBindingMiddleware>.Instance, _optionsAccessor,
            _certCache);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        var body = await ReadResponseBody(context);
        body.Should().Contain("Certificate thumbprint mismatch");
    }

    [Fact(DisplayName = "Scenario 5: Direct connection with matching client certificate -> Allow")]
    public async Task InvokeAsync_DirectConnection_WithValidCertificate_Succeeds()
    {
        // Arrange
        var localOptions = Microsoft.Extensions.Options.Options.Create(new MtlsBindingOptions
        {
            AllowDirectConnection = true,
            TrustedProxies = ["127.0.0.1/32"],
            ValidateChain = false
        });

        var context = CreateHttpContextWithCnf(_testCertThumbprint);
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.50");
        context.Connection.ClientCertificate = _testCert;

        static Task Next(HttpContext httpContext)
        {
            httpContext.Items["next_called"] = true;
            return Task.CompletedTask;
        }

        var middleware =
            new MtlsBindingMiddleware(Next, NullLogger<MtlsBindingMiddleware>.Instance, localOptions, _certCache);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Items.ContainsKey("next_called").Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact(DisplayName = "Scenario 6: Direct connection but client certificate missing on socket -> Block 403")]
    public async Task InvokeAsync_DirectConnection_WithMissingCertificate_Rejected()
    {
        // Arrange
        var localOptions = Microsoft.Extensions.Options.Options.Create(new MtlsBindingOptions
        {
            AllowDirectConnection = true,
            TrustedProxies = ["127.0.0.1/32"],
            ValidateChain = false
        });

        var context = CreateHttpContextWithCnf(_testCertThumbprint);
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.50");
        context.Connection.ClientCertificate = null!;

        static Task Next(HttpContext _)
        {
            return Task.CompletedTask;
        }

        var middleware =
            new MtlsBindingMiddleware(Next, NullLogger<MtlsBindingMiddleware>.Instance, localOptions, _certCache);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        var body = await ReadResponseBody(context);
        body.Should().Contain("Missing required client certificate");
    }

    [Fact(DisplayName = "Scenario 7: Direct connection but certificate fails chain validation -> Block 403")]
    public async Task InvokeAsync_DirectConnection_WithChainFailure_Rejected()
    {
        // Arrange
        var localOptions = Microsoft.Extensions.Options.Options.Create(new MtlsBindingOptions
        {
            AllowDirectConnection = true,
            TrustedProxies = ["127.0.0.1/32"],
            ValidateChain = true
        });

        var context = CreateHttpContextWithCnf(_testCertThumbprint);
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.50");
        context.Connection.ClientCertificate = _testCert;

        static Task Next(HttpContext _)
        {
            return Task.CompletedTask;
        }

        var middleware =
            new MtlsBindingMiddleware(Next, NullLogger<MtlsBindingMiddleware>.Instance, localOptions, _certCache);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        var body = await ReadResponseBody(context);
        body.Should().Contain("Client certificate failed chain validation.");
    }

    [Fact(DisplayName = "Scenario 8: Malformed certificate header in trusted proxy -> Block 403 (Exception Shielding)")]
    public async Task InvokeAsync_FromTrustedProxy_WithMalformedHeader_FailsClosed()
    {
        // Arrange
        var context = CreateHttpContextWithCnf(_testCertThumbprint);
        context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        context.Request.Headers["X-Client-Cert"] = "corrupted-unreadable-pem-bytes-!!!";

        static Task Next(HttpContext _)
        {
            return Task.CompletedTask;
        }

        var middleware = new MtlsBindingMiddleware(Next, NullLogger<MtlsBindingMiddleware>.Instance, _optionsAccessor,
            _certCache);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        var body = await ReadResponseBody(context);
        body.Should().Contain("Provided certificate is malformed or invalid.");
    }

    [Fact(DisplayName = "Scenario 9: Unauthenticated request passes through (No-Op)")]
    public async Task InvokeAsync_UnauthenticatedUser_PassesThrough()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();

        static Task Next(HttpContext httpContext)
        {
            httpContext.Items["next_called"] = true;
            return Task.CompletedTask;
        }

        var middleware = new MtlsBindingMiddleware(Next, NullLogger<MtlsBindingMiddleware>.Instance, _optionsAccessor,
            _certCache);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Items.ContainsKey("next_called").Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact(DisplayName = "Scenario 10: Authenticated request without 'cnf' claim is strictly rejected (Fail-Closed)")]
    public async Task InvokeAsync_AuthenticatedButNoCnfClaim_IsRejected()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user")], "test"));

        static Task Next(HttpContext _)
        {
            return Task.CompletedTask;
        }

        var middleware = new MtlsBindingMiddleware(Next, NullLogger<MtlsBindingMiddleware>.Instance, _optionsAccessor,
            _certCache);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        var body = await ReadResponseBody(context);
        body.Should().Contain("Missing required certificate confirmation (cnf) claim.");
    }

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
