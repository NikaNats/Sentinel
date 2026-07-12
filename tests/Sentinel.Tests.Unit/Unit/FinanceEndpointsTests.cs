using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Sentinel.Domain.Auth.Rar;
using Sentinel.RAR;
using Sentinel.Sample.MinimalApi;
using Sentinel.Sample.MinimalApi.Endpoints;
using Sentinel.Security.Abstractions.Idempotency;
using Sentinel.Security.Abstractions.Session;

namespace Sentinel.Tests.Unit.Unit;

public sealed class FinanceEndpointsTests : IClassFixture<FinanceEndpointsTests.LocalTestFactory>
{
    private const string TargetEndpoint = "/v1/finance/transfer";
    private readonly LocalTestFactory _factory;

    public FinanceEndpointsTests(LocalTestFactory factory)
    {
        _factory = factory;
        _factory.ResetMocks();
    }

    private static async Task<HttpResponseMessage> SendTransferRequestAsync(
        HttpClient client,
        TransferRequest payload)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, TargetEndpoint);

        request.Content = JsonContent.Create<TransferRequest>(payload, SampleJsonContext.Default.TransferRequest);

        request.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString());

        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    [Fact(DisplayName = "✅ Finance: Transfer within signed RAR bounds returns 200 OK and status Approved")]
    public async Task ExecuteTransfer_WithValidParamsWithinRarBounds_Returns200Approved()
    {
        using var client = _factory.CreateClient();
        var requestPayload = new TransferRequest("txn-unique-123", 50000.00m, "USD", "acc-98765");

        using var response = await SendTransferRequestAsync(client, requestPayload);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result =
            await response.Content.ReadFromJsonAsync<TransferResponse>(SampleJsonContext.Default.TransferResponse);
        result.Should().NotBeNull();
        result!.Status.Should().Be("Approved");
        result.TransactionId.Should().Be("txn-unique-123");
    }

    [Theory(DisplayName =
        "🔴 Finance: Invalid monetary amount (zero or negative) is blocked and returns 400 Bad Request")]
    [InlineData(0)]
    [InlineData(-100.50)]
    public async Task ExecuteTransfer_WithInvalidAmount_Returns400BadRequest(decimal invalidAmount)
    {
        using var client = _factory.CreateClient();
        var requestPayload = new TransferRequest("txn-unique-123", invalidAmount, "USD", "acc-98765");

        using var response = await SendTransferRequestAsync(client, requestPayload);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var problem =
            await response.Content.ReadFromJsonAsync<ProblemDetails>(SampleJsonContext.Default.ProblemDetails);
        problem.Should().NotBeNull();
        problem!.Detail.Should().Contain("Amount must be greater than zero");
    }

    [Theory(DisplayName =
        "🔴 Finance: Invalid currency code (non-ISO 4217 or contains numbers/length mismatches) is blocked and returns 400")]
    [InlineData("US")]
    [InlineData("USDE")]
    [InlineData("US1")]
    [InlineData("   ")]
    public async Task ExecuteTransfer_WithInvalidCurrency_Returns400BadRequest(string invalidCurrency)
    {
        using var client = _factory.CreateClient();
        var requestPayload = new TransferRequest("txn-unique-123", 500.00m, invalidCurrency, "acc-98765");

        using var response = await SendTransferRequestAsync(client, requestPayload);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var problem =
            await response.Content.ReadFromJsonAsync<ProblemDetails>(SampleJsonContext.Default.ProblemDetails);
        problem.Should().NotBeNull();
        problem!.Detail.Should().Contain("Currency must be a 3-letter ISO 4217 code");
    }

    [Theory(DisplayName =
        "🔴 Finance: Missing required fields (TransactionId or DestinationAccount) is blocked and returns 400")]
    [InlineData("", "acc-98765", "TransactionId is required")]
    [InlineData("txn-123", "", "DestinationAccount is required")]
    public async Task ExecuteTransfer_WithMissingFields_Returns400BadRequest(string txnId, string account,
        string expectedError)
    {
        using var client = _factory.CreateClient();
        var requestPayload = new TransferRequest(txnId, 500.00m, "USD", account);

        using var response = await SendTransferRequestAsync(client, requestPayload);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var problem =
            await response.Content.ReadFromJsonAsync<ProblemDetails>(SampleJsonContext.Default.ProblemDetails);
        problem.Should().NotBeNull();
        problem!.Detail.Should().Contain(expectedError);
    }

    [Fact(DisplayName =
        "🔴 Finance: Transfer exceeding signed RAR bounds (e.g. higher amount than authorized) is blocked with 403")]
    public async Task ExecuteTransfer_ExceedingRarBounds_Returns403Forbidden()
    {
        _factory.RarValidatorMock
            .Setup(x => x.ValidateByType(It.IsAny<AuthorizationDetail[]>(), "urn:sentinel:finance:transfer",
                It.IsAny<string>()))
            .Returns(RarValidationResult.Failure("Authorization bounds exceeded"));

        using var client = _factory.CreateClient();
        var requestPayload = new TransferRequest("txn-unique-123", 100000.00m, "USD", "acc-98765");

        using var response = await SendTransferRequestAsync(client, requestPayload);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var problem =
            await response.Content.ReadFromJsonAsync<ProblemDetails>(SampleJsonContext.Default.ProblemDetails);
        problem.Should().NotBeNull();
        problem!.Type.Should().Be("/errors/authorization-bounds-exceeded");
    }

    public sealed class LocalTestFactory : WebApplicationFactory<Program>
    {
        public Mock<IIdempotencyStore> IdempotencyStoreMock { get; } = new(MockBehavior.Strict);
        public Mock<IRarValidator> RarValidatorMock { get; } = new(MockBehavior.Strict);

        public void ResetMocks()
        {
            IdempotencyStoreMock.Reset();
            RarValidatorMock.Reset();

            IdempotencyStoreMock
                .Setup(x => x.TryAcquireAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((IdempotencyAcquireResult.Acquired, (CachedHttpResponse?)null));

            IdempotencyStoreMock
                .Setup(x => x.ReleaseAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            IdempotencyStoreMock
                .Setup(x => x.MarkCompletedAsync(It.IsAny<string>(), It.IsAny<CachedHttpResponse>(),
                    It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            RarValidatorMock
                .Setup(x => x.ValidateByType(It.IsAny<AuthorizationDetail[]>(), "urn:sentinel:finance:transfer",
                    It.IsAny<string>()))
                .Returns(RarValidationResult.Success(new AuthorizationDetail("urn:sentinel:finance:transfer")));
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureTestServices(services =>
            {
                var dbDependentServices = services.Where(d =>
                    d.ServiceType == typeof(ISessionBlacklistCache) ||
                    d.ServiceType == typeof(Application.Common.Abstractions.ISessionBlacklistCache) ||
                    d.ImplementationType?.Name == "HybridSessionBlacklistCache").ToList();

                foreach (var service in dbDependentServices)
                {
                    services.Remove(service);
                }

                var blacklistMock = new Mock<ISessionBlacklistCache>();
                services.AddSingleton(blacklistMock.Object);

                var appBlacklistMock = new Mock<Application.Common.Abstractions.ISessionBlacklistCache>();
                services.AddSingleton(appBlacklistMock.Object);

                services.AddAuthentication();
                services.AddAuthorization();

                services.AddSingleton(IdempotencyStoreMock.Object);
                services.AddSingleton(RarValidatorMock.Object);
            });

            builder.Configure(app =>
            {
                app.UseRouting();

                app.UseAuthentication();

                app.Use(async (context, next) =>
                {
                    var claims = new[]
                    {
                        new Claim("sub", "user-uuid-12345"),
                        new Claim("acr", "acr3"),
                        new Claim("scope", "finance"),
                        new Claim("authorization_details",
                            "[{\"type\":\"urn:sentinel:finance:transfer\",\"transaction_id\":\"txn-unique-123\",\"amount\":50000.00,\"currency\":\"USD\"}]")
                    };
                    context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
                    await next();
                });

                app.UseAuthorization();

                app.UseEndpoints(endpoints => { endpoints.MapFinanceEndpoints("v1/finance"); });
            });
        }
    }
}
