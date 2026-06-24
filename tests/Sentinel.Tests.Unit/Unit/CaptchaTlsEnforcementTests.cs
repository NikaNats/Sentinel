using System;
using System.Collections.Generic;
using System.Net.Http;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Infrastructure.DependencyInjection;
using Xunit;

namespace Sentinel.Tests.Unit.Unit;

public sealed class CaptchaTlsEnforcementTests
{
    [Fact(DisplayName = "🔐 DI Integrity: Verify ICaptchaService HttpClient is registered under its Name with secure headers")]
    public void Verify_CaptchaHttpClient_IsRegisteredCorrectly()
    {
        var services = new ServiceCollection();

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sentinel:Security:Captcha:SecretKey"] = "0x4AAAAAAABB-MOCK-SECRET",
                ["Sentinel:Security:Captcha:VerificationUrl"] = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
            })
            .Build();

        services.AddSingleton<IConfiguration>(config);
        services.AddLogging();

        services.AddSecurityControls(config);

        using var provider = services.BuildServiceProvider();
        var clientFactory = provider.GetRequiredService<IHttpClientFactory>();

        var clientName = nameof(ICaptchaService);
        using var client = clientFactory.CreateClient(clientName);

        client.Should().NotBeNull();

        client.DefaultRequestHeaders.UserAgent.ToString().Should().Contain("Sentinel-Security-Gateway/2.0",
            "The CAPTCHA client must carry the enterprise custom User-Agent header.");

        client.BaseAddress.Should().Be(new Uri("https://challenges.cloudflare.com/turnstile/v0/siteverify"),
            "The CAPTCHA client must point to the configured verification URL.");
    }
}
