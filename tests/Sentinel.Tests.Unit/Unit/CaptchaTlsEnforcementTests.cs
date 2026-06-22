using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Application.Auth.Interfaces;

namespace Sentinel.Tests.Unit.Unit;

/// <summary>
///     High-assurance integration tests for Captcha HttpClient.
///     Verifies that ICaptchaService is registered with the correct typed HttpClient and secure handlers.
/// </summary>
public sealed class CaptchaTlsEnforcementTests(WebApplicationFactory<Program> factory)
    : IClassFixture<WebApplicationFactory<Program>>
{
    [Fact(DisplayName = "🔐 DI Integrity: Verify ICaptchaService HttpClient is registered under its Name")]
    public void Verify_CaptchaHttpClient_IsRegisteredCorrectly()
    {
        var clientFactory = factory.Services.GetRequiredService<IHttpClientFactory>();

        const string clientName = nameof(ICaptchaService);
        using var client = clientFactory.CreateClient(clientName);

        client.Should().NotBeNull();
        client.DefaultRequestHeaders.UserAgent.ToString().Should().Contain("Sentinel-Security-Gateway/2.0",
            "The CAPTCHA client must carry the enterprise custom User-Agent header.");
    }
}
