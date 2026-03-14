using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Infrastructure.Auth;
using Sentinel.Infrastructure.Telemetry;
using System.Net;
using System.Net.Http;

namespace Sentinel.Tests.Unit;

public sealed class KeycloakAuthRevocationServiceTests
{
    [Fact]
    public async Task RevokeCurrentSessionAsync_WhenKeycloakReturnsSuccess_ReturnsTrue()
    {
        var httpClient = new HttpClient(new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var emitter = new Mock<ISecurityEventEmitter>();
        var sut = new KeycloakAuthRevocationService(httpClient, BuildConfig(), emitter.Object, NullLogger<KeycloakAuthRevocationService>.Instance);

        var result = await sut.RevokeCurrentSessionAsync("refresh-token", CancellationToken.None);

        Assert.True(result);
    }

    [Fact]
    public async Task RevokeAllSessionsAsync_WhenKeycloakReturnsSuccess_EmitsSecuritySignal()
    {
        var httpClient = new HttpClient(new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NoContent)));
        var emitter = new Mock<ISecurityEventEmitter>();
        var sut = new KeycloakAuthRevocationService(httpClient, BuildConfig(), emitter.Object, NullLogger<KeycloakAuthRevocationService>.Instance);

        var result = await sut.RevokeAllSessionsAsync("user-1", CancellationToken.None);

        Assert.True(result);
        emitter.Verify(x => x.EmitAuthFailure("global_logout_triggered", "user-1", "internal"), Times.Once);
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
