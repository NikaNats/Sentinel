using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Sentinel.AspNetCore.Authentication;
using Sentinel.Security.Abstractions.Session;

namespace Sentinel.Tests.Unit.Unit;

public sealed class SentinelJwtBearerTests
{
    [Fact(DisplayName = "🔴 JwtBearer: missing token returns RFC 9457 401 with WWW-Authenticate")]
    public async Task MissingToken_Returns401Problem()
    {
        using var host = await StartHostAsync();
        using var client = host.GetTestClient();

        using var response = await client.GetAsync("/protected", TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/problem+json");
        response.Headers.WwwAuthenticate.Should().NotBeEmpty();
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        body.Should().Contain("Missing or invalid token");
    }

    [Theory(DisplayName = "🔴 JwtBearer: invalid token detail never leaks validator internals")]
    [InlineData("Bearer")]
    [InlineData("DPoP")]
    public async Task InvalidToken_DoesNotLeakExceptionText(string scheme)
    {
        using var host = await StartHostAsync();
        using var client = host.GetTestClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/protected");
        request.Headers.Authorization = new AuthenticationHeaderValue(scheme, "eyJhbGciOiJQUzI1NiJ9.e30.c2ln");

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        body.Should().Contain("The access token is invalid");
        body.Should().NotContain("IDX");
    }

    [Fact(DisplayName = "✅ JwtBearer: Sentinel's own rejection reason reaches the client")]
    public async Task SentinelRejection_ReasonIsEchoed()
    {
        var blacklist = new Mock<ISessionBlacklistCache>();
        blacklist.Setup(x => x.IsBlacklistedAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var host = await StartHostAsync(blacklist.Object, key);
        using var client = host.GetTestClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/protected");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", SignToken(key));

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        body.Should().Contain("User account has been globally revoked or locked.");
    }

    [Fact(DisplayName = "✅ AddSentinelJwtBearer applies strict validation defaults")]
    public async Task Defaults_AreStrict()
    {
        using var host = await StartHostAsync();
        var options = host.Services
            .GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions>>()
            .Get("Bearer");

        options.MapInboundClaims.Should().BeFalse();
        options.RequireHttpsMetadata.Should().BeTrue();
        options.TokenValidationParameters.ClockSkew.Should().Be(TimeSpan.Zero);
        options.TokenValidationParameters.ValidIssuer.Should().Be("https://idp.example.test/realms/sentinel");
        options.TokenValidationParameters.ValidAlgorithms.Should().BeEquivalentTo("PS256", "ES256");
    }

    private static string SignToken(ECDsa key) =>
        new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://idp.example.test/realms/sentinel",
            Audience = "sentinel-api",
            Subject = new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim("sub", "user-1"),
                new System.Security.Claims.Claim("sid", "session-1")
            ]),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key) { KeyId = "k" },
                SecurityAlgorithms.EcdsaSha256)
        });

    private static async Task<IHost> StartHostAsync(ISessionBlacklistCache? blacklist = null, ECDsa? key = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(blacklist ?? Mock.Of<ISessionBlacklistCache>());
        builder.Services.AddAuthentication()
            .AddSentinelJwtBearer("https://idp.example.test/realms/sentinel/", "sentinel-api", options =>
            {
                // No network: validate against a local key instead of fetching discovery metadata.
                options.ConfigurationManager = null;
                options.TokenValidationParameters.IssuerSigningKey =
                    new ECDsaSecurityKey(key ?? ECDsa.Create()) { KeyId = "k" };
            });
        builder.Services.AddAuthorization();

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/protected", () => "ok").RequireAuthorization();
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }
}
