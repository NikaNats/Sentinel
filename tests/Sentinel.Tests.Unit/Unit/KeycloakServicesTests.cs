using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Moq.Protected;
using Sentinel.Keycloak;
using Sentinel.Security.Abstractions.Token;
using Xunit;

namespace Sentinel.Tests.Unit.Unit;

public sealed class KeycloakServicesTests : IDisposable
{
    private readonly Mock<HttpMessageHandler> _handlerMock;
    private readonly HttpClient _httpClient;
    private readonly IOptions<KeycloakOptions> _options;
    private readonly IOptions<KeycloakOptions> _emptyOptions;

    public KeycloakServicesTests()
    {
        _handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        _httpClient = new HttpClient(_handlerMock.Object)
        {
            BaseAddress = new Uri("https://keycloak.local/realms/sentinel")
        };

        _options = Microsoft.Extensions.Options.Options.Create(new KeycloakOptions
        {
            Authority = "https://keycloak.local/realms/sentinel",
            Audience = "sentinel-api"
        });

        _emptyOptions = Microsoft.Extensions.Options.Options.Create(new KeycloakOptions
        {
            Authority = "",
            Audience = ""
        });

        _handlerMock.Protected()
            .Setup("Dispose", ItExpr.IsAny<bool>())
            .Verifiable();
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }

    // =========================================================================
    // 🔄 KeycloakTokenRefreshService Tests (Target: 100% Coverage)
    // =========================================================================

    [Fact(DisplayName = "✅ Refresh: Missing configuration must immediately return failed result")]
    public async Task RefreshTokenAsync_WithMissingConfig_ReturnsFailedResult()
    {
        // Arrange
        var sut = new KeycloakTokenRefreshService(_httpClient, _emptyOptions, NullLogger<KeycloakTokenRefreshService>.Instance);

        // Act
        var result = await sut.RefreshTokenAsync("refresh-token", "dpop-proof", "ip-hash", TestContext.Current.CancellationToken);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.IsReuseDetected.Should().BeFalse();
    }

    [Fact(DisplayName = "✅ Refresh: Valid credentials and DPoP proof return new rotated tokens")]
    public async Task RefreshTokenAsync_WithValidParams_ReturnsRotatedTokens()
    {
        // Arrange
        var payload = new Dictionary<string, string>
        {
            ["access_token"] = "new-access-token-123",
            ["refresh_token"] = "rotated-refresh-token-456"
        };

        SetupMockHttpResponse(HttpMethod.Post, "/realms/sentinel/protocol/openid-connect/token", HttpStatusCode.OK, payload);

        var sut = new KeycloakTokenRefreshService(_httpClient, _options, NullLogger<KeycloakTokenRefreshService>.Instance);

        // Act
        var result = await sut.RefreshTokenAsync("old-refresh-token", "dpop-proof", "ip-hash", TestContext.Current.CancellationToken);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.AccessToken.Should().Be("new-access-token-123");
        result.RefreshToken.Should().Be("rotated-refresh-token-456");
        result.IsReuseDetected.Should().BeFalse();
    }

    [Fact(DisplayName = "🔴 Refresh: Token reuse (invalid_grant) triggers token theft alert")]
    public async Task RefreshTokenAsync_WhenTokenReuseDetected_TriggersAlert()
    {
        // Arrange
        var errorPayload = new Dictionary<string, string>
        {
            ["error"] = "invalid_grant",
            ["error_description"] = "Token already used"
        };

        SetupMockHttpResponse(HttpMethod.Post, "/realms/sentinel/protocol/openid-connect/token", HttpStatusCode.BadRequest, errorPayload);

        var sut = new KeycloakTokenRefreshService(_httpClient, _options, NullLogger<KeycloakTokenRefreshService>.Instance);

        // Act
        var result = await sut.RefreshTokenAsync("reused-refresh-token", "dpop-proof", "ip-hash", TestContext.Current.CancellationToken);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.IsReuseDetected.Should().BeTrue("Reusing a consumed refresh token must trigger the token-theft flag.");
    }

    [Fact(DisplayName = "🔴 Refresh: Non-JSON invalid_grant response still triggers token theft alert")]
    public async Task RefreshTokenAsync_WithNonJsonInvalidGrant_TriggersAlert()
    {
        // Arrange
        SetupMockHtmlResponse(HttpMethod.Post, "/realms/sentinel/protocol/openid-connect/token", HttpStatusCode.BadRequest, "Error: invalid_grant - token already used");

        var sut = new KeycloakTokenRefreshService(_httpClient, _options, NullLogger<KeycloakTokenRefreshService>.Instance);

        // Act
        var result = await sut.RefreshTokenAsync("reused-refresh-token", "dpop-proof", "ip-hash", TestContext.Current.CancellationToken);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.IsReuseDetected.Should().BeTrue();
    }

    [Fact(DisplayName = "⚠️ Refresh: Malformed JSON response must fail closed safely")]
    public async Task RefreshTokenAsync_WithMalformedJson_FailsClosed()
    {
        // Arrange
        SetupMockHtmlResponse(HttpMethod.Post, "/realms/sentinel/protocol/openid-connect/token", HttpStatusCode.OK, "{invalid-json-structure}");

        var sut = new KeycloakTokenRefreshService(_httpClient, _options, NullLogger<KeycloakTokenRefreshService>.Instance);

        // Act
        var result = await sut.RefreshTokenAsync("refresh-token", "dpop-proof", "ip-hash", TestContext.Current.CancellationToken);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.IsReuseDetected.Should().BeFalse();
    }

    [Fact(DisplayName = "⚠️ Refresh: Connection failure must fail closed")]
    public async Task RefreshTokenAsync_WhenNetworkFails_ReturnsFailedResult()
    {
        // Arrange
        _handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new HttpRequestException("Connection refused"));

        var sut = new KeycloakTokenRefreshService(_httpClient, _options, NullLogger<KeycloakTokenRefreshService>.Instance);

        // Act
        var result = await sut.RefreshTokenAsync("refresh-token", "dpop-proof", "ip-hash", TestContext.Current.CancellationToken);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.IsReuseDetected.Should().BeFalse();
    }

    // =========================================================================
    // 🛡️ KeycloakUmaPermissionService Tests (Target: 100% Coverage)
    // =========================================================================

    [Fact(DisplayName = "✅ UMA: Missing configuration must immediately deny access")]
    public async Task HasAccessAsync_WithMissingConfig_ReturnsFalse()
    {
        // Arrange
        var sut = new KeycloakUmaPermissionService(_httpClient, _emptyOptions, NullLogger<KeycloakUmaPermissionService>.Instance);

        // Act
        var hasAccess = await sut.HasAccessAsync("token", "resource", "scope", TestContext.Current.CancellationToken);

        // Assert
        hasAccess.Should().BeFalse("Incomplete configuration must fail closed.");
    }

    [Fact(DisplayName = "✅ UMA: Access granted when UMA returns 200 OK")]
    public async Task HasAccessAsync_WhenUmaPermits_ReturnsTrue()
    {
        // Arrange
        SetupMockHttpResponse(HttpMethod.Post, "/realms/sentinel/protocol/openid-connect/token", HttpStatusCode.OK, new Dictionary<string, string>());

        var sut = new KeycloakUmaPermissionService(_httpClient, _options, NullLogger<KeycloakUmaPermissionService>.Instance);

        // Act
        var hasAccess = await sut.HasAccessAsync("valid-token", "document-123", "document:read", TestContext.Current.CancellationToken);

        // Assert
        hasAccess.Should().BeTrue();
    }

    [Fact(DisplayName = "🔴 UMA: Access denied when UMA returns 403 Forbidden")]
    public async Task HasAccessAsync_WhenUmaDenies_ReturnsFalse()
    {
        // Arrange
        SetupMockHttpResponse(HttpMethod.Post, "/realms/sentinel/protocol/openid-connect/token", HttpStatusCode.Forbidden, new Dictionary<string, string>());

        var sut = new KeycloakUmaPermissionService(_httpClient, _options, NullLogger<KeycloakUmaPermissionService>.Instance);

        // Act
        var hasAccess = await sut.HasAccessAsync("valid-token", "document-123", "document:read", TestContext.Current.CancellationToken);

        // Assert
        hasAccess.Should().BeFalse();
    }

    [Fact(DisplayName = "⚠️ UMA: Network exception must fail closed")]
    public async Task HasAccessAsync_WhenNetworkFails_ReturnsFalse()
    {
        // Arrange
        _handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new HttpRequestException("UMA endpoint timeout"));

        var sut = new KeycloakUmaPermissionService(_httpClient, _options, NullLogger<KeycloakUmaPermissionService>.Instance);

        // Act
        var hasAccess = await sut.HasAccessAsync("token", "resource", "scope", TestContext.Current.CancellationToken);

        // Assert
        hasAccess.Should().BeFalse("All infrastructure failures must fail closed.");
    }

    // --- Mocks Setup Helpers ---

    private void SetupMockHttpResponse<T>(HttpMethod method, string path, HttpStatusCode statusCode, T? responseBody) where T : class
    {
        _handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req =>
                    req.Method == method &&
                    req.RequestUri!.AbsolutePath == path),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = statusCode,
                Content = responseBody != null ? JsonContent.Create<T>(responseBody) : null
            });
    }

    private void SetupMockHtmlResponse(HttpMethod method, string path, HttpStatusCode statusCode, string content)
    {
        _handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req =>
                    req.Method == method &&
                    req.RequestUri!.AbsolutePath == path),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = statusCode,
                Content = new StringContent(content)
            });
    }
}
