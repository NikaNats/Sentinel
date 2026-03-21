using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Infrastructure.Auth;

namespace Sentinel.Tests.Unit;

public sealed class KeycloakTokenExchangeServiceTests
{
    [Fact]
    public async Task ExchangeExternalTokenAsync_WhenSuccessful_ReturnsTokens()
    {
        using var handler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                "{\"access_token\":\"acc\",\"refresh_token\":\"ref\",\"token_type\":\"DPoP\",\"expires_in\":300}")
        });
        using var httpClient = new HttpClient(handler);

        var service = new KeycloakTokenExchangeService(
            httpClient,
            BuildOptions(),
            NullLogger<KeycloakTokenExchangeService>.Instance);

        var result = await service.ExchangeExternalTokenAsync("google-token", "google", "proof", "pkce-verifier",
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal("acc", result!.AccessToken);
        Assert.Equal("DPoP", result.TokenType);
        Assert.Equal("proof", handler.LastRequest?.Headers.GetValues("DPoP").FirstOrDefault());
    }

    [Fact]
    public async Task ExchangeExternalTokenAsync_WhenProviderRejects_ReturnsNull()
    {
        using var handler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.BadRequest));
        using var httpClient = new HttpClient(handler);
        var service = new KeycloakTokenExchangeService(
            httpClient,
            BuildOptions(),
            NullLogger<KeycloakTokenExchangeService>.Instance);

        var result = await service.ExchangeExternalTokenAsync("google-token", "google", "proof", "pkce-verifier",
            CancellationToken.None);

        Assert.Null(result);
    }

    private static IOptions<KeycloakOptions> BuildOptions()
    {
        return Options.Create(new KeycloakOptions
        {
            Authority = "https://keycloak.local/realms/sentinel",
            Audience = "sentinel-api"
        });
    }

    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory)
        : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(responseFactory(request));
        }
    }
}
