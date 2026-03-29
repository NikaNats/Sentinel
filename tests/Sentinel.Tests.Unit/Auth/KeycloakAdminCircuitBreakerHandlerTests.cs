using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Sentinel.Keycloak.Handlers;

namespace Sentinel.Tests.Unit.Auth;

public sealed class KeycloakAdminCircuitBreakerHandlerTests
{
    [Fact]
    public async Task SendAsync_AfterFiveTransientFailures_OpensCircuitAndShortCircuits()
    {
        var timeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var state = new KeycloakAdminCircuitBreakerState(timeProvider);
        var logger = NullLogger<KeycloakAdminCircuitBreakerHandler>.Instance;
        using var innerHandler = new CountingHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        using var client = CreateClient(state, logger, innerHandler);

        for (var i = 0; i < 5; i++)
        {
            using var response = await client.GetAsync("https://keycloak.local/admin");
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        }

        using var shortCircuitResponse = await client.GetAsync("https://keycloak.local/admin");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, shortCircuitResponse.StatusCode);
        Assert.Equal("Keycloak admin circuit is open", shortCircuitResponse.ReasonPhrase);
        Assert.Equal(5, innerHandler.CallCount);
    }

    [Fact]
    public async Task SendAsync_AfterBreakDuration_ClosesCircuitAndRetriesDownstream()
    {
        var timeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var state = new KeycloakAdminCircuitBreakerState(timeProvider);
        var logger = NullLogger<KeycloakAdminCircuitBreakerHandler>.Instance;
        using var innerHandler = new CountingHandler(callNumber =>
            callNumber <= 5
                ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
                : new HttpResponseMessage(HttpStatusCode.OK));
        using var client = CreateClient(state, logger, innerHandler);

        for (var i = 0; i < 5; i++)
        {
            using var _ = await client.GetAsync("https://keycloak.local/admin");
        }

        using var shortCircuitResponse = await client.GetAsync("https://keycloak.local/admin");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, shortCircuitResponse.StatusCode);
        Assert.Equal(5, innerHandler.CallCount);

        timeProvider.Advance(TimeSpan.FromSeconds(31));

        using var recoveredResponse = await client.GetAsync("https://keycloak.local/admin");
        Assert.Equal(HttpStatusCode.OK, recoveredResponse.StatusCode);
        Assert.Equal(6, innerHandler.CallCount);
    }

    private static HttpClient CreateClient(KeycloakAdminCircuitBreakerState state,
        ILogger<KeycloakAdminCircuitBreakerHandler> logger,
        HttpMessageHandler innerHandler)
    {
        var circuitBreakerHandler = new KeycloakAdminCircuitBreakerHandler(state, logger)
        {
            InnerHandler = innerHandler
        };

        return new HttpClient(circuitBreakerHandler);
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
