using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Auth;
using System.Net;
using System.Net.Http;
using System.Text;

namespace Sentinel.Tests.Unit;

public sealed class KeycloakTokenRefreshServiceTests
{
    [Fact]
    public async Task RefreshTokenAsync_WhenSuccess_ReturnsRotatedTokens()
    {
        var body = "{\"access_token\":\"new-access\",\"refresh_token\":\"new-refresh\"}";
        var httpClient = new HttpClient(new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        }));

        var emitter = new Mock<ISecurityEventEmitter>();
        var sut = new KeycloakTokenRefreshService(httpClient, BuildConfig(), emitter.Object, NullLogger<KeycloakTokenRefreshService>.Instance);

        var result = await sut.RefreshTokenAsync("old-refresh", "proof", "HASHED_IP", CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("new-access", result.AccessToken);
        Assert.Equal("new-refresh", result.RefreshToken);
        Assert.False(result.IsReuseDetected);
        emitter.Verify(x => x.EmitAuthFailure(It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task RefreshTokenAsync_WhenInvalidGrant_EmitsCriticalSecuritySignal()
    {
        var body = "{\"error\":\"invalid_grant\",\"error_description\":\"Token already used\"}";
        var httpClient = new HttpClient(new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        }));

        var emitter = new Mock<ISecurityEventEmitter>();
        var sut = new KeycloakTokenRefreshService(httpClient, BuildConfig(), emitter.Object, NullLogger<KeycloakTokenRefreshService>.Instance);

        var result = await sut.RefreshTokenAsync("stolen-refresh", "proof", "HASHED_IP", CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.True(result.IsReuseDetected);
        emitter.Verify(x => x.EmitAuthFailure("refresh_token_reuse_detected", null, "HASHED_IP"), Times.Once);
    }

    [Fact]
    public async Task RefreshTokenAsync_WhenNonReuseFailure_ReturnsUnauthorizedStateWithoutReuseFlag()
    {
        var body = "{\"error\":\"invalid_request\"}";
        var httpClient = new HttpClient(new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        }));

        var emitter = new Mock<ISecurityEventEmitter>();
        var sut = new KeycloakTokenRefreshService(httpClient, BuildConfig(), emitter.Object, NullLogger<KeycloakTokenRefreshService>.Instance);

        var result = await sut.RefreshTokenAsync("bad-refresh", "proof", "HASHED_IP", CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.False(result.IsReuseDetected);
        emitter.Verify(x => x.EmitAuthFailure(It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<string>()), Times.Never);
    }

    private static IConfiguration BuildConfig()
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Keycloak:Authority"] = "https://keycloak.local/realms/sentinel",
                ["Keycloak:Audience"] = "sentinel-api"
            })
            .Build();
    }

    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(responseFactory(request));
        }
    }
}
