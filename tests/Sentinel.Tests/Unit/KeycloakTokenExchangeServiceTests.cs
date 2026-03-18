using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Infrastructure.Auth;

namespace Sentinel.Tests.Unit;

public sealed class KeycloakTokenExchangeServiceTests
{
    [Fact]
    public async Task ExchangeExternalTokenAsync_WhenSuccessful_ReturnsTokens()
    {
        var handler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"access_token\":\"acc\",\"refresh_token\":\"ref\",\"token_type\":\"DPoP\",\"expires_in\":300}")
        });

        var service = new KeycloakTokenExchangeService(
            new HttpClient(handler),
            BuildConfiguration(),
            NullLogger<KeycloakTokenExchangeService>.Instance);

        var result = await service.ExchangeExternalTokenAsync("google-token", "google", "proof", CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal("acc", result!.AccessToken);
        Assert.Equal("DPoP", result.TokenType);
        Assert.Equal("proof", handler.LastRequest?.Headers.GetValues("DPoP").FirstOrDefault());
    }

    [Fact]
    public async Task ExchangeExternalTokenAsync_WhenProviderRejects_ReturnsNull()
    {
        var handler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.BadRequest));
        var service = new KeycloakTokenExchangeService(
            new HttpClient(handler),
            BuildConfiguration(),
            NullLogger<KeycloakTokenExchangeService>.Instance);

        var result = await service.ExchangeExternalTokenAsync("google-token", "google", "proof", CancellationToken.None);

        Assert.Null(result);
    }

    private static IConfiguration BuildConfiguration()
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
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(responseFactory(request));
        }
    }
}
