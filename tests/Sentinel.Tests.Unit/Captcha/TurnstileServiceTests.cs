using System.Net;
using Microsoft.Extensions.Options;
using Sentinel.Security.Captcha;
using Xunit;
using FluentAssertions;

namespace Sentinel.Tests.Unit.Captcha;

public sealed class TurnstileServiceTests
{
    [Fact]
    public async Task VerifyAsync_WhenConfigOrTokenIsMissing_ReturnsFalseInstantly()
    {
        var sut = new TurnstileService(new HttpClient(), Options.Create(new CaptchaOptions { SecretKey = "" }));

        var result1 = await sut.VerifyAsync("valid-token", CancellationToken.None);
        var result2 = await sut.VerifyAsync("", CancellationToken.None); // empty token

        result1.Should().BeFalse();
        result2.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyAsync_WhenCloudflareReturnsError_ReturnsFalse()
    {
        using var handler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var sut = new TurnstileService(new HttpClient(handler), Options.Create(new CaptchaOptions { SecretKey = "secret" }));

        var result = await sut.VerifyAsync("some-token", CancellationToken.None);

        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyAsync_WhenCloudflareReturnsSuccessJson_ReturnsTrue()
    {
        using var handler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"success\":true}")
        });
        var sut = new TurnstileService(new HttpClient(handler), Options.Create(new CaptchaOptions { SecretKey = "secret" }));

        var result = await sut.VerifyAsync("some-token", CancellationToken.None);

        result.Should().BeTrue();
    }

    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(responseFactory(request));
    }
}
