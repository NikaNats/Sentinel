using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.Keycloak;
using FluentAssertions;

namespace Sentinel.Tests.Unit.Keycloak;

public sealed class KeycloakAdminTokenProviderTests
{
    [Fact]
    public async Task GetAccessTokenAsync_WhenCalledTwiceWithinExpiry_ReturnsCachedTokenWithoutHttpCall()
    {
        // Arrange
        var callCount = 0;
        using var handler = new StubHttpMessageHandler(_ =>
        {
            callCount++;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"access_token\":\"token-123\",\"expires_in\":300}")
            };
        });
        using var httpClient = new HttpClient(handler);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(x => x.CreateClient("keycloak-admin")).Returns(httpClient);

        using var sut = new KeycloakAdminTokenProvider(
            factoryMock.Object,
            BuildOptions(),
            NullLogger<KeycloakAdminTokenProvider>.Instance);

        // Act
        var token1 = await sut.GetAccessTokenAsync(CancellationToken.None);
        var token2 = await sut.GetAccessTokenAsync(CancellationToken.None);

        // Assert
        token1.Should().Be("token-123");
        token2.Should().Be("token-123");
        callCount.Should().Be(1, "Second call should use cached token from SemaphoreSlim-protected cache");
    }

    [Fact]
    public async Task GetAccessTokenAsync_WhenHttpFails_ReturnsNullAndLogs()
    {
        // Arrange
        using var handler = new StubHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Content = new StringContent("invalid_client")
            });
        using var httpClient = new HttpClient(handler);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(x => x.CreateClient("keycloak-admin")).Returns(httpClient);

        using var sut = new KeycloakAdminTokenProvider(
            factoryMock.Object,
            BuildOptions(),
            NullLogger<KeycloakAdminTokenProvider>.Instance);

        // Act
        var token = await sut.GetAccessTokenAsync(CancellationToken.None);

        // Assert
        token.Should().BeNull("HTTP 401 should result in null token");
    }

    [Fact]
    public async Task GetAccessTokenAsync_WhenJsonIsMissingAccessToken_ReturnsNull()
    {
        // Arrange
        using var handler = new StubHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"other_field\":\"value\"}")
            });
        using var httpClient = new HttpClient(handler);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(x => x.CreateClient("keycloak-admin")).Returns(httpClient);

        using var sut = new KeycloakAdminTokenProvider(
            factoryMock.Object,
            BuildOptions(),
            NullLogger<KeycloakAdminTokenProvider>.Instance);

        // Act
        var token = await sut.GetAccessTokenAsync(CancellationToken.None);

        // Assert
        token.Should().BeNull("Missing access_token in JSON should return null");
    }

    [Fact]
    public async Task GetAccessTokenAsync_WhenHttpStreamThrows_CatchesThrownException()
    {
        // Arrange
        var factoryMock = new Mock<IHttpClientFactory>();
        var httpClientMock = new Mock<HttpClient>();

        httpClientMock
            .Setup(x => x.SendAsync(It.IsAny<HttpRequestMessage>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Connection timeout"));

        factoryMock.Setup(x => x.CreateClient("keycloak-admin")).Returns(httpClientMock.Object);

        using var sut = new KeycloakAdminTokenProvider(
            factoryMock.Object,
            BuildOptions(),
            NullLogger<KeycloakAdminTokenProvider>.Instance);

        // Act
        var token = await sut.GetAccessTokenAsync(CancellationToken.None);

        // Assert
        token.Should().BeNull("HttpRequestException should be caught and return null");
    }

    [Fact]
    public async Task GetAccessTokenAsync_ConcurrentRequests_OnlyOneHttpCallMade()
    {
        // Arrange
        var callCount = 0;
        using var delayHandler = new StubHttpMessageHandler(async _ =>
        {
            callCount++;
            await Task.Delay(100); // Simulate slow response
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"access_token\":\"token-concurrent\",\"expires_in\":300}")
            };
        });
        using var httpClient = new HttpClient(delayHandler);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(x => x.CreateClient("keycloak-admin")).Returns(httpClient);

        using var sut = new KeycloakAdminTokenProvider(
            factoryMock.Object,
            BuildOptions(),
            NullLogger<KeycloakAdminTokenProvider>.Instance);

        // Act - Multiple concurrent calls
        var tasks = Enumerable.Range(0, 5)
            .Select(_ => sut.GetAccessTokenAsync(CancellationToken.None))
            .ToList();

        var tokens = await Task.WhenAll(tasks);

        // Assert
        tokens.Should().AllBe("token-concurrent");
        callCount.Should().Be(1, "SemaphoreSlim should ensure only one HTTP call despite concurrent requests");
    }

    [Fact]
    public async Task GetAccessTokenAsync_WithMissingConfiguration_ReturnsNull()
    {
        // Arrange
        var emptyOptions = Options.Create(new KeycloakOptions
        {
            Authority = "",  // Missing authority
            Admin = new KeycloakAdminOptions { ClientId = "", ClientSecret = "" }
        });

        var factoryMock = new Mock<IHttpClientFactory>();
        using var sut = new KeycloakAdminTokenProvider(
            factoryMock.Object,
            emptyOptions,
            NullLogger<KeycloakAdminTokenProvider>.Instance);

        // Act
        var token = await sut.GetAccessTokenAsync(CancellationToken.None);

        // Assert
        token.Should().BeNull("Missing configuration should return null without making HTTP call");
        factoryMock.Verify(x => x.CreateClient(It.IsAny<string>()), Times.Never);
    }

    private static IOptions<KeycloakOptions> BuildOptions() =>
        Options.Create(new KeycloakOptions
        {
            Authority = "https://keycloak.local/realms/sentinel",
            Admin = new KeycloakAdminOptions { ClientId = "cli", ClientSecret = "sec" }
        });

    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> responseFactory) : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _responseFactory = responseFactory;

        public StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> syncFactory)
            : this(r => Task.FromResult(syncFactory(r)))
        {
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            _responseFactory(request);
    }
}
