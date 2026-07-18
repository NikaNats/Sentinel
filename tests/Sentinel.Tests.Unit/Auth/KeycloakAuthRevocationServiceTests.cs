using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Moq.Protected;
using Sentinel.Keycloak;

namespace Sentinel.Tests.Unit.Auth;

public sealed class KeycloakAuthRevocationServiceTests : IDisposable
{
    private readonly KeycloakAdminTokenProvider _adminTokenProvider;
    private readonly Mock<HttpMessageHandler> _handlerMock;
    private readonly HttpClient _httpClient;
    private readonly Mock<IHttpClientFactory> _httpClientFactoryMock;
    private readonly IOptions<KeycloakOptions> _options;

    public KeycloakAuthRevocationServiceTests()
    {
        _handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        _httpClient = new HttpClient(_handlerMock.Object)
        {
            BaseAddress = new Uri("https://keycloak.local/realms/sentinel")
        };

        _handlerMock.Protected()
            .Setup("Dispose", ItExpr.IsAny<bool>())
            .Verifiable();

        _httpClientFactoryMock = new Mock<IHttpClientFactory>();
        _httpClientFactoryMock
            .Setup(x => x.CreateClient("keycloak-admin"))
            .Returns(_httpClient);

        _options = Microsoft.Extensions.Options.Options.Create(new KeycloakOptions
        {
            Authority = "https://keycloak.local/realms/sentinel",
            Audience = "sentinel-api",
            Admin = new KeycloakAdminOptions
            {
                ClientId = "admin-cli",
                ClientSecret = "secret"
            }
        });

        var mockTokenProviderHandler = new Mock<HttpMessageHandler>();

        mockTokenProviderHandler.Protected()
            .Setup("Dispose", ItExpr.IsAny<bool>());

        var mockTokenProviderClient = new HttpClient(mockTokenProviderHandler.Object);
        var mockFactory = new Mock<IHttpClientFactory>();
        mockFactory.Setup(x => x.CreateClient("keycloak-admin")).Returns(mockTokenProviderClient);

        _adminTokenProvider = new KeycloakAdminTokenProvider(
            mockFactory.Object,
            _options,
            NullLogger<KeycloakAdminTokenProvider>.Instance,
            TimeProvider.System);

        mockTokenProviderHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = JsonContent.Create(new { access_token = "mock-admin-token", expires_in = 3600 })
            });
    }

    public void Dispose()
    {
        _httpClient.Dispose();
        _adminTokenProvider.Dispose();
        _handlerMock.Verify();
    }

    [Fact(DisplayName =
        "✅ KeycloakSessionResponse deserializer successfully populates read-only Clients dictionary under AOT rules")]
    public void Verify_KeycloakSessionResponse_Deserialization_WithReadOnlyClients_Succeeds()
    {
        // Arrange
        const string jsonPayload = """
                                   [
                                     {
                                       "id": "session-unique-123",
                                       "ipAddress": "192.168.1.50",
                                       "start": 1700000000000,
                                       "lastAccess": 1700000100000,
                                       "clients": {
                                         "sentinel-api": { "active": true },
                                         "other-client": { "active": false }
                                       }
                                     }
                                   ]
                                   """;

        // Act
        var sessions = JsonSerializer.Deserialize(
            jsonPayload,
            KeycloakJsonContext.Default.ListKeycloakSessionResponse);

        // Assert
        sessions.Should().NotBeNull();
        sessions.Should().HaveCount(1);

        var session = sessions![0];
        session.Id.Should().Be("session-unique-123");
        session.IpAddress.Should().Be("192.168.1.50");

        session.Clients.Should().NotBeNull();
        session.Clients.Should().HaveCount(2);
        session.Clients.Should().ContainKey("sentinel-api");
        session.Clients.Should().ContainKey("other-client");
    }

    [Fact(DisplayName =
        "✅ KeycloakAuthRevocationService.GetActiveSessionsAsync parses payload and maps client keys perfectly")]
    public async Task GetActiveSessionsAsync_WithValidJsonPayload_ParsesAndMapsClientKeys()
    {
        // Arrange
        const string jsonPayload = """
                                   [
                                     {
                                       "id": "session-active-999",
                                       "ipAddress": "10.0.0.1",
                                       "start": 1700000000000,
                                       "lastAccess": 1700000100000,
                                       "clients": {
                                         "sentinel-portal": {},
                                         "mobile-gateway": {}
                                       }
                                     }
                                   ]
                                   """;

        _handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req =>
                    req.Method == HttpMethod.Get &&
                    req.RequestUri!.AbsolutePath.EndsWith("/sessions", StringComparison.Ordinal)),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json")
            });

        var sut = new KeycloakAuthRevocationService(
            _httpClient,
            _httpClientFactoryMock.Object,
            _adminTokenProvider,
            _options,
            NullLogger<KeycloakAuthRevocationService>.Instance);

        // Act
        var activeSessions = await sut.GetActiveSessionsAsync("user-uuid-123", TestContext.Current.CancellationToken);

        // Assert
        activeSessions.Should().NotBeNull();
        activeSessions.Should().HaveCount(1);

        var mappedSession = activeSessions.First();
        mappedSession.SessionId.Should().Be("session-active-999");
        mappedSession.IpAddress.Should().Be("10.0.0.1");
        mappedSession.StartedAtUtc.Should().Be(DateTimeOffset.FromUnixTimeMilliseconds(1700000000000));
        mappedSession.LastAccessUtc.Should().Be(DateTimeOffset.FromUnixTimeMilliseconds(1700000100000));

        mappedSession.Clients.Should().HaveCount(2);
        mappedSession.Clients.Should().BeEquivalentTo("sentinel-portal", "mobile-gateway");
    }
}
