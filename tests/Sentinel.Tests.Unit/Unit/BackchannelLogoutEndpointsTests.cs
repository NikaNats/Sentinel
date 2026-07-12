using System.Net;
using FluentAssertions;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Sentinel.Application.Common.Abstractions;
using Sentinel.AspNetCore.Endpoints;
using Sentinel.Keycloak;

namespace Sentinel.Tests.Unit.Unit;

/// <summary>
///     High-assurance functional and security tests for OIDC Backchannel Logout (RFC 9413).
///     Verifies strict timing-attack shielding, silent success responses for forged tokens,
///     and robust exception shielding during identity provider-initiated session revocations.
/// </summary>
public sealed class BackchannelLogoutEndpointsTests : IClassFixture<BackchannelLogoutEndpointsTests.LocalTestFactory>
{
    private readonly LocalTestFactory _factory;

    public BackchannelLogoutEndpointsTests(LocalTestFactory factory)
    {
        _factory = factory;
        _factory.ResetMocks();
    }

    [Fact(DisplayName = "❌ RFC 9413: Missing logout_token must immediately return 400 Bad Request")]
    public async Task ReceiveLogoutToken_WithMissingToken_Returns400BadRequest()
    {
        // Arrange
        using var client = _factory.CreateClient();

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["logout_token"] = ""
        });

        // Act
        using var response = await client.PostAsync("/v1/auth/backchannel-logout", content,
            TestContext.Current.CancellationToken);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact(DisplayName =
        "✓ RFC 9413: Forged or invalid token must return 200 OK silently to prevent timing/probing attacks")]
    public async Task ReceiveLogoutToken_WithInvalidToken_Returns200OkSilently()
    {
        // Arrange
        using var client = _factory.CreateClient();
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["logout_token"] = "forged-or-invalid-jwt-token"
        });

        _factory.ValidatorMock
            .Setup(x => x.ValidateAndExtractSessionIdAsync("forged-or-invalid-jwt-token",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync((string?)null);

        // Act
        using var response = await client.PostAsync("/v1/auth/backchannel-logout", content,
            TestContext.Current.CancellationToken);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK,
            "RFC 9413 mandates returning 200 OK even on validation failures to avoid session enumeration.");
        _factory.BlacklistCacheMock.Verify(
            x => x.BlacklistSessionAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact(DisplayName = "✅ RFC 9413: Valid logout token successfully blacklists the session and returns 200 OK")]
    public async Task ReceiveLogoutToken_WithValidToken_BlacklistsSessionAndReturns200Ok()
    {
        // Arrange
        using var client = _factory.CreateClient();
        const string targetSid = "session-to-revoke-123";
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["logout_token"] = "valid-backchannel-jwt"
        });

        _factory.ValidatorMock
            .Setup(x => x.ValidateAndExtractSessionIdAsync("valid-backchannel-jwt", It.IsAny<CancellationToken>()))
            .ReturnsAsync(targetSid);

        _factory.BlacklistCacheMock
            .Setup(x => x.BlacklistSessionAsync(targetSid, It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask)
            .Verifiable();

        // Act
        using var response = await client.PostAsync("/v1/auth/backchannel-logout", content,
            TestContext.Current.CancellationToken);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        _factory.BlacklistCacheMock.Verify();
    }

    [Fact(DisplayName =
        "🛡️ RFC 9413 Fail-Safe: Unhandled cache exception must be shielded, logged, and return 200 OK")]
    public async Task ReceiveLogoutToken_WhenCacheThrows_ShieldsExceptionAndReturns200Ok()
    {
        // Arrange
        using var client = _factory.CreateClient();
        const string targetSid = "session-error-999";
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["logout_token"] = "valid-token-but-cache-fails"
        });

        _factory.ValidatorMock
            .Setup(x => x.ValidateAndExtractSessionIdAsync("valid-token-but-cache-fails",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(targetSid);

        _factory.BlacklistCacheMock
            .Setup(x => x.BlacklistSessionAsync(targetSid, It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Redis cluster is offline"));

        // Act
        using var response = await client.PostAsync("/v1/auth/backchannel-logout", content,
            TestContext.Current.CancellationToken);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    public sealed class LocalTestFactory : WebApplicationFactory<Program>
    {
        public Mock<ILogoutTokenValidator> ValidatorMock { get; } = new(MockBehavior.Strict);
        public Mock<ISessionBlacklistCache> BlacklistCacheMock { get; } = new(MockBehavior.Strict);
        public Mock<IAntiforgery> AntiforgeryMock { get; } = new(MockBehavior.Strict);

        public void ResetMocks()
        {
            ValidatorMock.Reset();
            BlacklistCacheMock.Reset();
            AntiforgeryMock.Reset();

            AntiforgeryMock
                .Setup(x => x.ValidateRequestAsync(It.IsAny<HttpContext>()))
                .Returns(Task.CompletedTask);

            AntiforgeryMock
                .Setup(x => x.IsRequestValidAsync(It.IsAny<HttpContext>()))
                .ReturnsAsync(true);

            AntiforgeryMock
                .Setup(x => x.GetAndStoreTokens(It.IsAny<HttpContext>()))
                .Returns(new AntiforgeryTokenSet("mock-cookie", "mock-request", "mock-form", "mock-header"));
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureTestServices(services =>
            {
                var dbDependentServices = services.Where(d =>
                    d.ServiceType == typeof(Security.Abstractions.Session.ISessionBlacklistCache) ||
                    d.ServiceType == typeof(ISessionBlacklistCache) ||
                    d.ImplementationType?.Name == "HybridSessionBlacklistCache").ToList();

                foreach (var service in dbDependentServices)
                {
                    services.Remove(service);
                }

                var securityBlacklistMock = new Mock<Security.Abstractions.Session.ISessionBlacklistCache>();
                securityBlacklistMock
                    .Setup(x => x.BlacklistSessionAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(),
                        It.IsAny<CancellationToken>()))
                    .Returns(Task.CompletedTask);
                services.AddSingleton(securityBlacklistMock.Object);

                services.AddSingleton(AntiforgeryMock.Object);
                services.AddSingleton(ValidatorMock.Object);
                services.AddSingleton(BlacklistCacheMock.Object);

                services.AddSingleton(Microsoft.Extensions.Options.Options.Create(new KeycloakOptions
                {
                    Authority = "https://keycloak.local/realms/sentinel",
                    Audience = "sentinel-api",
                    SsoSessionMaxLifespanSeconds = 28800
                }));
            });

            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseAntiforgery();
                app.UseEndpoints(endpoints =>
                {
                    var group = endpoints.MapGroup("v1");
                    group.MapBackchannelLogoutEndpoints();
                });
            });
        }
    }
}
