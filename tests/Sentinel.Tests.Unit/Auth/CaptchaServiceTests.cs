using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Moq.Protected;
using Sentinel.Application.Auth.Options;
using Sentinel.Infrastructure.Auth;

namespace Sentinel.Tests.Unit.Auth;

public sealed class CaptchaServiceTests
{
    private static IOptions<CaptchaOptions> CreateOptions(bool enabled = true) =>
        Microsoft.Extensions.Options.Options.Create(new CaptchaOptions
        {
            Enabled = enabled,
            SecretKey = "0x4AAAAAAABB-MOCK-SECRET",
            VerificationUrl = new Uri("https://challenges.cloudflare.com/turnstile/v0/siteverify", UriKind.Absolute)
        });

    [Fact(DisplayName = "✅ Successful CAPTCHA validation")]
    public async Task VerifyAsync_ValidToken_ReturnsTrue()
    {
        // Arrange
        var handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        handlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent("{\"success\":true,\"hostname\":\"sentinel.local\"}")
            });

        var httpClient = new HttpClient(handlerMock.Object)
            { BaseAddress = new Uri("https://challenges.cloudflare.com", UriKind.Absolute) };
        var sut = new CloudflareTurnstileCaptchaService(httpClient, CreateOptions(),
            NullLogger<CloudflareTurnstileCaptchaService>.Instance);

        // Act
        var result = await sut.VerifyAsync("valid-token", TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result);
    }

    [Fact(DisplayName = "⚠️ Fail-Closed: Request is securely blocked when provider returns an error")]
    public async Task VerifyAsync_ProviderReturns500_ReturnsFalse()
    {
        // Arrange
        var handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        handlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.InternalServerError
            });

        var httpClient = new HttpClient(handlerMock.Object)
            { BaseAddress = new Uri("https://challenges.cloudflare.com", UriKind.Absolute) };
        var sut = new CloudflareTurnstileCaptchaService(httpClient, CreateOptions(),
            NullLogger<CloudflareTurnstileCaptchaService>.Instance);

        // Act
        var result = await sut.VerifyAsync("some-token", TestContext.Current.CancellationToken);

        // Assert
        Assert.False(result);
    }
}
