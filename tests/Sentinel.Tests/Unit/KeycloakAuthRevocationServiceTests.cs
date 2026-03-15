// Sentinel Security API - FAPI 2.0 Compliant
using System.Net;
using System.Net.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Auth;

namespace Sentinel.Tests.Unit;

public sealed class KeycloakAuthRevocationServiceTests
{
    [Fact]
    public async Task RevokeCurrentSessionAsync_WhenKeycloakReturnsSuccess_ReturnsTrue()
    {
        StubHttpMessageHandler publicHandler = new(_ => new HttpResponseMessage(HttpStatusCode.OK));
        HttpClient httpClient = new(publicHandler);
        StubHttpMessageHandler adminHandler = new(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        Mock<IHttpClientFactory> httpClientFactory = BuildHttpClientFactory(adminHandler);

        Mock<ISecurityEventEmitter> emitter = new();
        KeycloakAdminTokenProvider adminTokenProvider = new(httpClientFactory.Object, BuildConfig(), NullLogger<KeycloakAdminTokenProvider>.Instance);
        KeycloakAuthRevocationService sut = new(
            httpClient,
            httpClientFactory.Object,
            adminTokenProvider,
            BuildConfig(),
            emitter.Object,
            NullLogger<KeycloakAuthRevocationService>.Instance);

        bool result = await sut.RevokeCurrentSessionAsync("refresh-token", CancellationToken.None);

        Assert.True(result);
        _ = Assert.Single(publicHandler.Requests);
        Assert.Empty(adminHandler.Requests);
    }

    [Fact]
    public async Task RevokeAllSessionsAsync_WhenKeycloakReturnsSuccess_EmitsSecuritySignal()
    {
        StubHttpMessageHandler publicHandler = new(_ => new HttpResponseMessage(HttpStatusCode.OK));
        HttpClient httpClient = new(publicHandler);
        StubHttpMessageHandler adminHandler = new(request =>
        {
            return request.RequestUri is not null && request.RequestUri.AbsolutePath.EndsWith("/protocol/openid-connect/token", StringComparison.Ordinal)
                ? new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"access_token\":\"admin-token\",\"expires_in\":300}")
                }
                : new HttpResponseMessage(HttpStatusCode.NoContent);
        });

        Mock<IHttpClientFactory> httpClientFactory = BuildHttpClientFactory(adminHandler);
        Mock<ISecurityEventEmitter> emitter = new();
        KeycloakAdminTokenProvider adminTokenProvider = new(httpClientFactory.Object, BuildConfig(), NullLogger<KeycloakAdminTokenProvider>.Instance);
        KeycloakAuthRevocationService sut = new(
            httpClient,
            httpClientFactory.Object,
            adminTokenProvider,
            BuildConfig(),
            emitter.Object,
            NullLogger<KeycloakAuthRevocationService>.Instance);

        bool result = await sut.RevokeAllSessionsAsync("user-1", CancellationToken.None);

        Assert.True(result);
        emitter.Verify(x => x.EmitAuthFailure("global_logout_triggered", "user-1", "internal"), Times.Once);

        Assert.Equal(2, adminHandler.Requests.Count);
        Assert.Equal("/admin/realms/sentinel/users/user-1/logout", adminHandler.Requests[1].RequestUri?.AbsolutePath);
        Assert.Equal("Bearer", adminHandler.Requests[1].Headers.Authorization?.Scheme);
        Assert.Equal("admin-token", adminHandler.Requests[1].Headers.Authorization?.Parameter);
        Assert.Empty(publicHandler.Requests);
    }

    private static IConfiguration BuildConfig() =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Keycloak:Authority"] = "https://keycloak.local/realms/sentinel",
                ["Keycloak:Audience"] = "sentinel-api",
                ["Keycloak:Admin:ClientId"] = "sentinel-admin-cli",
                ["Keycloak:Admin:ClientSecret"] = "sentinel-secret"
            })
            .Build();

    private static Mock<IHttpClientFactory> BuildHttpClientFactory(StubHttpMessageHandler adminHandler)
    {
        Mock<IHttpClientFactory> factory = new();
        _ = factory
            .Setup(x => x.CreateClient("keycloak-admin"))
            .Returns(new HttpClient(adminHandler));

        return factory;
    }

    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(CloneRequest(request));
            return Task.FromResult(responseFactory(request));
        }

        private static HttpRequestMessage CloneRequest(HttpRequestMessage request)
        {
            HttpRequestMessage clone = new(request.Method, request.RequestUri);

            foreach (KeyValuePair<string, IEnumerable<string>> header in request.Headers)
            {
                _ = clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (request.Content is not null)
            {
                string content = request.Content.ReadAsStringAsync(CancellationToken.None).GetAwaiter().GetResult();
                clone.Content = new StringContent(content);

                foreach (KeyValuePair<string, IEnumerable<string>> header in request.Content.Headers)
                {
                    _ = clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            return clone;
        }
    }
}
