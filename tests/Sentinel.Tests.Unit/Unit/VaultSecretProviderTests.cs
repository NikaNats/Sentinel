using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Moq.Protected;
using Sentinel.Providers.Vault;

namespace Sentinel.Tests.Unit.Unit;

public sealed class VaultSecretProviderTests : IDisposable
{
    private const string FallbackToken = "hvs.mocked-fallback-jwt-token-value";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    private readonly Mock<HttpMessageHandler> _handlerMock;
    private readonly HttpClient _httpClient;
    private readonly VaultOptions _options;

    public VaultSecretProviderTests()
    {
        _handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        _httpClient = new HttpClient(_handlerMock.Object)
        {
            BaseAddress = new Uri("https://vault.internal:8200")
        };
        _options = new VaultOptions("https://vault.internal:8200", "sentinel-api", FallbackToken);

        _handlerMock.Protected()
            .Setup("Dispose", ItExpr.IsAny<bool>())
            .Verifiable();
    }

    public void Dispose() => _httpClient.Dispose();

    [Fact(DisplayName = "✅ GetSecretAsync: Successful auth and secret retrieval returns expected value")]
    public async Task GetSecretAsync_SuccessfulAuthAndRetrieval_ReturnsSecretValue()
    {
        const string secretPath = "sentinel/privacy";
        const string secretKey = "MasterPepper";
        const string expectedValue = "pepper-bytes-base64";

        var loginResponse = new VaultLoginResponse(new VaultAuthData("hvs.valid-client-token"));
        var secretResponse = new VaultSecretResponse(new VaultSecretData(new Dictionary<string, string>
            { [secretKey] = expectedValue }));

        SetupMockHttpResponse(HttpMethod.Post, "/v1/auth/kubernetes/login", HttpStatusCode.OK, loginResponse);
        SetupMockHttpResponse(HttpMethod.Get, $"/v1/secret/data/{secretPath}", HttpStatusCode.OK,
            secretResponse);

        using var sut = new VaultSecretProvider(_options, _httpClient, NullLogger<VaultSecretProvider>.Instance);

        var result = await sut.GetSecretAsync(secretPath, secretKey, TestContext.Current.CancellationToken);

        result.Should().Be(expectedValue);
    }

    [Fact(DisplayName = "⚡ Optimization: Subsequent secret requests use cached token without re-authenticating")]
    public async Task GetSecretAsync_UsesCachedToken_OnSubsequentCalls()
    {
        const string secretPath = "sentinel/privacy";
        const string secretKey = "MasterPepper";

        var loginResponse = new VaultLoginResponse(new VaultAuthData("hvs.valid-client-token"));
        var secretResponse =
            new VaultSecretResponse(new VaultSecretData(new Dictionary<string, string> { [secretKey] = "val" }));

        SetupMockHttpResponse(HttpMethod.Post, "/v1/auth/kubernetes/login", HttpStatusCode.OK, loginResponse);
        SetupMockHttpResponse(HttpMethod.Get, $"/v1/secret/data/{secretPath}", HttpStatusCode.OK,
            secretResponse);

        using var sut = new VaultSecretProvider(_options, _httpClient, NullLogger<VaultSecretProvider>.Instance);

        _ = await sut.GetSecretAsync(secretPath, secretKey, TestContext.Current.CancellationToken);
        _ = await sut.GetSecretAsync(secretPath, secretKey, TestContext.Current.CancellationToken);

        VerifyHttpCallCount(HttpMethod.Post, "/v1/auth/kubernetes/login", Times.Once());
    }

    [Fact(DisplayName = "🔴 Fail-Closed: Unauthorized token (403 on secret read) invalidates cache and throws")]
    public async Task GetSecretAsync_WhenSecretReadReturns403_InvalidatesTokenAndThrowsUnauthorizedAccess()
    {
        const string secretPath = "sentinel/privacy";
        const string secretKey = "MasterPepper";

        var loginResponse = new VaultLoginResponse(new VaultAuthData("hvs.valid-client-token"));

        SetupMockHttpResponse(HttpMethod.Post, "/v1/auth/kubernetes/login", HttpStatusCode.OK, loginResponse);
        SetupMockHttpResponse<VaultSecretResponse>(HttpMethod.Get, $"/v1/secret/data/{secretPath}",
            HttpStatusCode.Forbidden, null);

        using var sut = new VaultSecretProvider(_options, _httpClient, NullLogger<VaultSecretProvider>.Instance);

        var act = async () => await sut.GetSecretAsync(secretPath, secretKey, TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<UnauthorizedAccessException>();

        SetupMockHttpResponse(HttpMethod.Get, $"/v1/secret/data/{secretPath}", HttpStatusCode.OK,
            new VaultSecretResponse(new VaultSecretData(new Dictionary<string, string> { [secretKey] = "val" })));

        var retryResult = await sut.GetSecretAsync(secretPath, secretKey, TestContext.Current.CancellationToken);
        retryResult.Should().Be("val");
    }

    [Fact(DisplayName = "🌪️ Concurrency: Parallel secret requests only trigger login EXACTLY once")]
    public async Task GetSecretAsync_UnderHighConcurrency_OnlyAuthenticatesOnce()
    {
        const string secretPath = "sentinel/privacy";
        const string secretKey = "MasterPepper";

        var loginResponse = new VaultLoginResponse(new VaultAuthData("hvs.concurrent-token"));
        var secretResponse = new VaultSecretResponse(new VaultSecretData(new Dictionary<string, string>
            { [secretKey] = "shared-value" }));

        SetupMockHttpResponse(HttpMethod.Post, "/v1/auth/kubernetes/login", HttpStatusCode.OK, loginResponse);
        SetupMockHttpResponse(HttpMethod.Get, $"/v1/secret/data/{secretPath}", HttpStatusCode.OK,
            secretResponse);

        using var sut = new VaultSecretProvider(_options, _httpClient, NullLogger<VaultSecretProvider>.Instance);

        var tasks = new List<Task<string?>>();
        for (var i = 0; i < 20; i++)
        {
            tasks.Add(sut.GetSecretAsync(secretPath, secretKey, TestContext.Current.CancellationToken).AsTask());
        }

        var results = await Task.WhenAll(tasks);

        results.Should().AllBeEquivalentTo("shared-value");
        VerifyHttpCallCount(HttpMethod.Post, "/v1/auth/kubernetes/login", Times.Once());
    }

    [Fact(DisplayName = "❌ GetSecretAsync: Returns null if key is missing in the secret dictionary")]
    public async Task GetSecretAsync_WhenKeyIsMissing_ReturnsNull()
    {
        const string secretPath = "sentinel/privacy";
        const string secretKey = "NonExistentKey";

        var loginResponse = new VaultLoginResponse(new VaultAuthData("hvs.valid-token"));
        var secretResponse =
            new VaultSecretResponse(new VaultSecretData(new Dictionary<string, string> { ["OtherKey"] = "val" }));

        SetupMockHttpResponse(HttpMethod.Post, "/v1/auth/kubernetes/login", HttpStatusCode.OK, loginResponse);
        SetupMockHttpResponse(HttpMethod.Get, $"/v1/secret/data/{secretPath}", HttpStatusCode.OK,
            secretResponse);

        using var sut = new VaultSecretProvider(_options, _httpClient, NullLogger<VaultSecretProvider>.Instance);

        var result = await sut.GetSecretAsync(secretPath, secretKey, TestContext.Current.CancellationToken);

        result.Should().BeNull();
    }

    [Fact(DisplayName = "🔴 Fail-Closed: Throws InvalidOperationException when no token source is available")]
    public async Task EnsureAuthenticatedAsync_NoTokenAvailable_ThrowsInvalidOperationException()
    {
        var emptyOptions = new VaultOptions("https://vault.internal:8200", "sentinel-api");
        using var sut = new VaultSecretProvider(emptyOptions, _httpClient, NullLogger<VaultSecretProvider>.Instance);

        var act = async () => await sut.GetSecretAsync("path", "key", TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("K8s ServiceAccount JWT is missing and fallback token is empty.");
    }

    private void SetupMockHttpResponse<T>(HttpMethod method, string path, HttpStatusCode statusCode, T? responseBody)
        where T : class =>
        _handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req =>
                    req.Method == method &&
                    req.RequestUri!.AbsolutePath == path),
                ItExpr.IsAny<CancellationToken>())
            .Returns(() => Task.FromResult(new HttpResponseMessage
            {
                StatusCode = statusCode,
                Content = responseBody != null ? JsonContent.Create(responseBody, null, SerializerOptions) : null
            }));

    private void VerifyHttpCallCount(HttpMethod method, string path, Times times) =>
        _handlerMock.Protected()
            .Verify(
                "SendAsync",
                times,
                ItExpr.Is<HttpRequestMessage>(req =>
                    req.Method == method &&
                    req.RequestUri!.AbsolutePath == path),
                ItExpr.IsAny<CancellationToken>());
}
