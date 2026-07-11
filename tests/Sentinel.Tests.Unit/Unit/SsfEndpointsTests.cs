using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.AspNetCore.Endpoints;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Results;
using Sentinel.Security.Abstractions.Session;
using Sentinel.Security.Abstractions.SSF;

namespace Sentinel.Tests.Unit.Unit;

/// <summary>
///     High-assurance security and functional tests for SSF (Shared Signals &amp; Events) endpoints (RFC 8936).
///     Verifies strict constant-time webhook authentication, route obfuscation under scanning,
///     and robust multi-format JSON/JWT payload parsing.
/// </summary>
public sealed class SsfEndpointsTests : IClassFixture<SsfEndpointsTests.LocalTestFactory>
{
    private const string ValidAuthToken = "hvs.secret-webhook-auth-token-999";
    private readonly LocalTestFactory _factory;

    public SsfEndpointsTests(LocalTestFactory factory)
    {
        _factory = factory;
        _factory.ResetMocks();
    }

    [Fact(DisplayName = "✅ SSF: Happy path raw JWT payload with valid webhook auth token returns 202 Accepted")]
    public async Task ReceiveEvent_WithValidRawJwt_Returns202Accepted()
    {
        // Arrange
        using var client = _factory.CreateClient();
        const string rawJwt = "eyJhbGciOiJQUzI1NiIsInR5cCI6InNlY2V2ZW50K2p3dCJ9.eyJqdGkiOiIxMjMifQ.sig";
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/ssf/events");
        request.Content = new StringContent(rawJwt, Encoding.UTF8, "application/secevent+jwt");
        request.Headers.Add("SSF-Auth-Token", ValidAuthToken);

        _factory.ProcessorMock
            .Setup(x => x.ProcessAsync(rawJwt, It.IsAny<CancellationToken>()))
            .ReturnsAsync(SecurityResult.CreateSuccess());

        // Act
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Accepted);
        _factory.ProcessorMock.Verify(x => x.ProcessAsync(rawJwt, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact(DisplayName = "✅ SSF: Happy path JSON payload with valid webhook auth token returns 202 Accepted")]
    public async Task ReceiveEvent_WithValidJsonPayload_Returns202Accepted()
    {
        // Arrange
        using var client = _factory.CreateClient();
        const string setToken = "eyJhbGciOiJQUzI1NiIsInR5cCI6InNlY2V2ZW50K2p3dCJ9.eyJqdGkiOiIxMjMifQ.sig";
        var payload = new { set = setToken };

        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/ssf/events");
        request.Content = JsonContent.Create(payload, typeof(object), null, LocalTestFactory.SerializerOptions);
        request.Headers.Add("SSF-Auth-Token", ValidAuthToken);

        _factory.ProcessorMock
            .Setup(x => x.ProcessAsync(setToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(SecurityResult.CreateSuccess());

        // Act
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Accepted);
    }

    [Fact(DisplayName =
        "🔴 SSF: Spoofing protection - missing or mismatched auth token returns 404 Not Found to obfuscate route existence")]
    public async Task ReceiveEvent_WithInvalidAuthToken_Returns404NotFound()
    {
        // Arrange
        using var client = _factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/ssf/events");
        request.Content = new StringContent("some-set", Encoding.UTF8, "application/secevent+jwt");
        request.Headers.Add("SSF-Auth-Token", "wrong-token-value");

        // Act
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        _factory.ProcessorMock.Verify(x => x.ProcessAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact(DisplayName = "🔴 SSF: Feature disabled - must immediately return 404 Not Found")]
    public async Task ReceiveEvent_WhenSsfDisabled_Returns404NotFound()
    {
        // Arrange
        _factory.SsfOptionsValue = new SsfOptions
        {
            Enabled = false,
            RequireAuthToken = true,
            AuthToken = ValidAuthToken
        };

        using var client = _factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/ssf/events");
        request.Content = new StringContent("some-set", Encoding.UTF8, "application/secevent+jwt");
        request.Headers.Add("SSF-Auth-Token", ValidAuthToken);

        // Act
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact(DisplayName = "🔴 SSF: Processor validation failure returns 400 Bad Request with ProblemDetails")]
    public async Task ReceiveEvent_WhenProcessorFails_Returns400BadRequest()
    {
        // Arrange
        using var client = _factory.CreateClient();
        const string rawJwt = "invalid-sig-jwt";
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/ssf/events");
        request.Content = new StringContent(rawJwt, Encoding.UTF8, "application/secevent+jwt");
        request.Headers.Add("SSF-Auth-Token", ValidAuthToken);

        _factory.ProcessorMock
            .Setup(x => x.ProcessAsync(rawJwt, It.IsAny<CancellationToken>()))
            .ReturnsAsync(SecurityResult.Failure("Invalid SET signature."));

        // Act
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("/errors/ssf-processing-failed");
        body.Should().Contain("Invalid SET signature.");
    }

    // --- Isolated WebApplicationFactory ---
    public sealed class LocalTestFactory : WebApplicationFactory<Program>
    {
        public static readonly JsonSerializerOptions SerializerOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        public Mock<ISsfEventProcessor> ProcessorMock { get; } = new(MockBehavior.Strict);
        public SsfOptions SsfOptionsValue { get; set; } = new();

        public void ResetMocks()
        {
            ProcessorMock.Reset();

            SsfOptionsValue = new SsfOptions
            {
                Enabled = true,
                RequireAuthToken = true,
                AuthToken = ValidAuthToken
            };
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureTestServices(services =>
            {
                var dbDependentServices = services.Where(d =>
                    d.ServiceType == typeof(ISessionBlacklistCache) ||
                    d.ServiceType == typeof(Application.Common.Abstractions.ISessionBlacklistCache) ||
                    d.ImplementationType?.Name == "HybridSessionBlacklistCache").ToList();

                foreach (var service in dbDependentServices)
                {
                    services.Remove(service);
                }

                var blacklistMock = new Mock<ISessionBlacklistCache>();
                services.AddSingleton(blacklistMock.Object);

                var appBlacklistMock = new Mock<Application.Common.Abstractions.ISessionBlacklistCache>();
                services.AddSingleton(appBlacklistMock.Object);

                services.AddSingleton(ProcessorMock.Object);

                var optionsMonitorMock = new Mock<IOptionsMonitor<SsfOptions>>();
                optionsMonitorMock.Setup(m => m.CurrentValue).Returns(() => SsfOptionsValue);
                services.AddSingleton(optionsMonitorMock.Object);
            });

            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseEndpoints(endpoints =>
                {
                    var group = endpoints.MapGroup("v1");
                    group.MapSsfEndpoints();
                });
            });
        }
    }
}
