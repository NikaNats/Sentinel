using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Sentinel.Keycloak;

namespace Sentinel.Tests.Unit.Auth;

public sealed class KeycloakAdminTokenProviderTests
{
    [Fact]
    public async Task GetAccessTokenAsync_WhenCalledConcurrently_OnlyFetchesTokenOnce()
    {
        using var handler = new CountingHandler(_ =>
            CreateTokenResponse("token-a", expiresIn: 120));
        using var client = new HttpClient(handler);
        using var provider = CreateProvider(client, new FakeTimeProvider(DateTimeOffset.UtcNow));

        var calls = Enumerable.Range(0, 20)
            .Select(_ => provider.GetAccessTokenAsync(CancellationToken.None));

        var tokens = await Task.WhenAll(calls);

        Assert.All(tokens, token => Assert.Equal("token-a", token));
        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task GetAccessTokenAsync_WhenTokenIsNearExpiry_RefreshesToken()
    {
        using var handler = new CountingHandler(callNumber =>
            callNumber == 1
                ? CreateTokenResponse("token-initial", expiresIn: 31)
                : CreateTokenResponse("token-refreshed", expiresIn: 120));
        using var client = new HttpClient(handler);
        var fakeTime = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var provider = CreateProvider(client, fakeTime);

        var firstToken = await provider.GetAccessTokenAsync(CancellationToken.None);
        Assert.Equal("token-initial", firstToken);

        fakeTime.Advance(TimeSpan.FromSeconds(2));

        var refreshedToken = await provider.GetAccessTokenAsync(CancellationToken.None);
        Assert.Equal("token-refreshed", refreshedToken);
        Assert.Equal(2, handler.CallCount);
    }

    private static KeycloakAdminTokenProvider CreateProvider(HttpClient client, TimeProvider timeProvider)
    {
        var options = Microsoft.Extensions.Options.Options.Create(new KeycloakOptions
        {
            Authority = "https://keycloak.local/realms/sentinel",
            Audience = "sentinel-api",
            Admin = new KeycloakAdminOptions
            {
                ClientId = "admin-cli",
                ClientSecret = "top-secret"
            }
        });

        var logger = new Mock<ILogger<KeycloakAdminTokenProvider>>();
        var factory = new StubHttpClientFactory(client);

        return new KeycloakAdminTokenProvider(factory, options, logger.Object, timeProvider);
    }

    private static HttpResponseMessage CreateTokenResponse(string token, int expiresIn)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new TokenResponse(token, expiresIn))
        };
    }

    private sealed record TokenResponse(string access_token, int expires_in);

    private sealed class StubHttpClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }

    private sealed class CountingHandler(Func<int, HttpResponseMessage> responseFactory) : HttpMessageHandler
    {
        private int _callCount;

        public int CallCount => _callCount;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var callNumber = Interlocked.Increment(ref _callCount);
            return Task.FromResult(responseFactory(callNumber));
        }
    }
}
