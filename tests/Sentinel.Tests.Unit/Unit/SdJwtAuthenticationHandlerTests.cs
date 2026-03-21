using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Infrastructure.Auth;
using Sentinel.Infrastructure.Auth.SdJwt;

namespace Sentinel.Tests.Unit;

public sealed class SdJwtAuthenticationHandlerTests
{
    [Fact]
    public async Task AuthenticateAsync_WhenSdJwtDisabled_ReturnsNoResult()
    {
        var verifier = new Mock<ISdJwtVerifier>(MockBehavior.Strict);
        var handler = CreateHandler(verifier.Object, new SdJwtOptions { Enabled = false });
        var context = new DefaultHttpContext();

        await handler.InitializeAsync(new AuthenticationScheme("SdJwt", null, typeof(SdJwtAuthenticationHandler)),
            context);
        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.True(result.None);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenVerifierFails_ReturnsFail()
    {
        var verifier = new Mock<ISdJwtVerifier>();
        verifier.Setup(x =>
                x.VerifyPresentationAsync("issuer~disclosure~kb", "sentinel-api", "", It.IsAny<CancellationToken>()))
            .ReturnsAsync(SdJwtVerificationResult.Fail("boom"));
        var handler = CreateHandler(verifier.Object);
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "Bearer issuer~disclosure~kb";

        await handler.InitializeAsync(new AuthenticationScheme("SdJwt", null, typeof(SdJwtAuthenticationHandler)),
            context);
        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("boom", result.Failure?.Message);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenVerifierSucceeds_ReturnsTicket()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-1")], "SD-JWT"));
        var verifier = new Mock<ISdJwtVerifier>();
        verifier.Setup(x =>
                x.VerifyPresentationAsync("issuer~disclosure~kb", "sentinel-api", "nonce-1",
                    It.IsAny<CancellationToken>()))
            .ReturnsAsync(SdJwtVerificationResult.Success(principal));
        var handler = CreateHandler(verifier.Object);
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "SD-JWT issuer~disclosure~kb";
        context.Request.Headers["SD-JWT-Nonce"] = "nonce-1";

        await handler.InitializeAsync(new AuthenticationScheme("SdJwt", null, typeof(SdJwtAuthenticationHandler)),
            context);
        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.Equal("user-1", result.Principal?.FindFirst("sub")?.Value);
    }

    private static SdJwtAuthenticationHandler CreateHandler(ISdJwtVerifier verifier, SdJwtOptions? sdJwtOptions = null)
    {
        return new SdJwtAuthenticationHandler(
            new StaticOptionsMonitor<AuthenticationSchemeOptions>(new AuthenticationSchemeOptions()),
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            Options.Create(new KeycloakOptions
            {
                Authority = "https://issuer.example",
                Audience = "sentinel-api"
            }),
            Options.Create(sdJwtOptions ?? new SdJwtOptions { Enabled = true }),
            verifier);
    }

    private sealed class StaticOptionsMonitor<TOptions>(TOptions currentValue) : IOptionsMonitor<TOptions>
    {
        public TOptions CurrentValue { get; } = currentValue;

        public TOptions Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<TOptions, string?> listener) => null;
    }
}
