using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.AspNetCore.Middleware;

namespace Sentinel.Tests.Unit;

public sealed class MtlsBindingMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_WhenTokenIsMtlsBoundAndCertificateMissing_ReturnsForbidden()
    {
        using var cert = CreateCertificate();
        var expectedThumbprint = ComputeThumbprint(cert);
        var context = CreateAuthenticatedContext($"{{\"x5t#S256\":\"{expectedThumbprint}\"}}");

        RequestDelegate next = _ => Task.CompletedTask;
        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance);

        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenTokenIsMtlsBoundAndCertificateMatches_ContinuesPipeline()
    {
        using var cert = CreateCertificate();
        var expectedThumbprint = ComputeThumbprint(cert);
        var context = CreateAuthenticatedContext($"{{\"x5t#S256\":\"{expectedThumbprint}\"}}");
        context.Features.Set<ITlsConnectionFeature>(new TestTlsConnectionFeature(cert));

        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance);

        await middleware.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenUnauthenticatedAndAccessTokenHasMtlsBinding_RejectsWithoutCertificate()
    {
        using var cert = CreateCertificate();
        var expectedThumbprint = ComputeThumbprint(cert);

        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = $"DPoP {CreateAccessTokenWithCnf($"{{\"x5t#S256\":\"{expectedThumbprint}\"}}")}";

        RequestDelegate next = _ => Task.CompletedTask;
        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance);

        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenAuthenticatedWithoutMtlsBinding_ContinuesPipeline()
    {
        var context = CreateAuthenticatedContext("{\"jkt\":\"thumbprint\"}");

        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance);

        await middleware.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenUnauthenticatedAndAccessTokenWithoutMtlsBinding_ContinuesPipeline()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = $"DPoP {CreateAccessTokenWithCnf("{\"jkt\":\"thumbprint\"}")}";

        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new MtlsBindingMiddleware(next, NullLogger<MtlsBindingMiddleware>.Instance);

        await middleware.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    private static DefaultHttpContext CreateAuthenticatedContext(string cnfJson)
    {
        var context = new DefaultHttpContext();
        var claimsIdentity = new ClaimsIdentity(
            [
                new Claim("sub", "sentinel-worker"),
                new Claim("cnf", cnfJson)
            ],
            "test");

        context.User = new ClaimsPrincipal(claimsIdentity);
        return context;
    }

    private static string ComputeThumbprint(X509Certificate2 certificate)
    {
        var thumbprintHash = certificate.GetCertHash(HashAlgorithmName.SHA256);
        return Base64UrlEncoder.Encode(thumbprintHash);
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=sentinel-workload", rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static string CreateAccessTokenWithCnf(string cnfJson)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new ECDsaSecurityKey(ecdsa);

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["sub"] = "sentinel-worker",
                ["cnf"] = System.Text.Json.JsonDocument.Parse(cnfJson).RootElement.Clone(),
                ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()
            },
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256)
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private sealed class TestTlsConnectionFeature(X509Certificate2? clientCertificate) : ITlsConnectionFeature
    {
        public X509Certificate2? ClientCertificate { get; set; } = clientCertificate;

        public Task<X509Certificate2?> GetClientCertificateAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(ClientCertificate);
        }
    }
}
