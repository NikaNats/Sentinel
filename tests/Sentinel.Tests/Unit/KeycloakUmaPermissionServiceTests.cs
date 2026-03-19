using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Infrastructure.Auth;
using System.Net;
using System.Net.Http;

namespace Sentinel.Tests.Unit;

public sealed class KeycloakUmaPermissionServiceTests
{
    [Fact]
    public async Task HasAccessAsync_WhenUmaDecisionPermit_ReturnsTrue()
    {
        var httpClient = new HttpClient(new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var options = BuildOptions();
        var sut = new KeycloakUmaPermissionService(httpClient, options, NullLogger<KeycloakUmaPermissionService>.Instance);

        var result = await sut.HasAccessAsync("token", "doc-1", "document:read", CancellationToken.None);

        Assert.True(result);
    }

    [Fact]
    public async Task HasAccessAsync_WhenUmaDecisionDeny_ReturnsFalse()
    {
        var httpClient = new HttpClient(new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden)));
        var options = BuildOptions();
        var sut = new KeycloakUmaPermissionService(httpClient, options, NullLogger<KeycloakUmaPermissionService>.Instance);

        var result = await sut.HasAccessAsync("token", "doc-1", "document:read", CancellationToken.None);

        Assert.False(result);
    }

    [Fact]
    public async Task HasAccessAsync_WhenKeycloakUnavailable_FailsClosed()
    {
        var httpClient = new HttpClient(new StubHttpMessageHandler(_ => throw new HttpRequestException("offline")));
        var options = BuildOptions();
        var sut = new KeycloakUmaPermissionService(httpClient, options, NullLogger<KeycloakUmaPermissionService>.Instance);

        var result = await sut.HasAccessAsync("token", "doc-1", "document:read", CancellationToken.None);

        Assert.False(result);
    }

    private static IOptions<KeycloakOptions> BuildOptions()
    {
        return Options.Create(new KeycloakOptions
        {
            Authority = "https://keycloak.local/realms/sentinel",
            Audience = "sentinel-api"
        });
    }

    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(responseFactory(request));
        }
    }
}
