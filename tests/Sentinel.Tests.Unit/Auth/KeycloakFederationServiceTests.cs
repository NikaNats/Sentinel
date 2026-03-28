using System.Net;
using FluentAssertions;
using Sentinel.Infrastructure.Auth.Services;

namespace Sentinel.Tests.Unit.Auth;

public sealed class KeycloakFederationServiceTests
{
    [Fact]
    public async Task ConfigureGoogleProviderAsync_WhenMissingConfig_ReturnsEarly()
    {
        var httpClient = new HttpClient(new StubHttpMessageHandler(_ => throw new Exception("Should not be called")));
        var sut = new KeycloakFederationService(httpClient);

        // Act: Empty client ID
        await sut.ConfigureGoogleProviderAsync("", "secret", "flow");

        // Assert: Doesn't throw, just exits.
        true.Should().BeTrue();
    }

    [Fact]
    public async Task ConfigureGoogleProviderAsync_WhenProviderDoesNotExist_CallsPostToCreate()
    {
        var requestMethods = new List<HttpMethod>();
        using var handler = new StubHttpMessageHandler(req =>
        {
            requestMethods.Add(req.Method);
            if (req.Method == HttpMethod.Get)
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound); // Triggers Create
            }

            return new HttpResponseMessage(HttpStatusCode.Created);
        });

        var sut = new KeycloakFederationService(new HttpClient(handler) { BaseAddress = new Uri("https://keycloak") });

        await sut.ConfigureGoogleProviderAsync("cli-id", "sec", "flow");

        requestMethods.Should().ContainInOrder(HttpMethod.Get, HttpMethod.Post);
    }

    [Fact]
    public async Task ConfigureGoogleProviderAsync_WhenProviderExists_CallsPutToUpdate()
    {
        var requestMethods = new List<HttpMethod>();
        using var handler = new StubHttpMessageHandler(req =>
        {
            requestMethods.Add(req.Method);
            if (req.Method == HttpMethod.Get)
            {
                return new HttpResponseMessage(HttpStatusCode.OK); // Triggers Update
            }

            return new HttpResponseMessage(HttpStatusCode.NoContent);
        });

        var sut = new KeycloakFederationService(new HttpClient(handler) { BaseAddress = new Uri("https://keycloak") });

        await sut.ConfigureGoogleProviderAsync("cli-id", "sec", "flow");

        requestMethods.Should().ContainInOrder(HttpMethod.Get, HttpMethod.Put);
    }

    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
            => Task.FromResult(responseFactory(request));
    }
}
