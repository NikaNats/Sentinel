using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.AspNetCore.Filters;
using Sentinel.Security.Abstractions.Idempotency;

namespace Sentinel.Tests.Unit.Unit;

public sealed class RequireIdempotencyAttributeTests
{
    [Fact]
    public async Task InvokeAsync_WhenHeaderMissing_ReturnsBadRequest()
    {
        var store = new Mock<IIdempotencyStore>();
        var filter = CreateFilter(store);
        var context = CreateContext();

        var result = await filter.InvokeAsync(context,
            _ => throw new InvalidOperationException("should not execute"));

        var status = Assert.IsAssignableFrom<IStatusCodeHttpResult>(result);
        Assert.Equal(StatusCodes.Status400BadRequest, status.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenDuplicateKey_ReturnsConflict()
    {
        var store = new Mock<IIdempotencyStore>();

        store.Setup(x => x.TryAcquireAsync(
                It.IsAny<string>(),
                It.IsAny<TimeSpan>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync((IdempotencyAcquireResult.InProgress, (CachedHttpResponse?)null));

        var filter = CreateFilter(store);
        var context = CreateContext();
        context.HttpContext.Request.Headers["Idempotency-Key"] = "6f836f95-7f22-4eb9-b854-8e8be2df40e8";

        var result = await filter.InvokeAsync(context,
            _ => throw new InvalidOperationException("should not execute"));

        var status = Assert.IsAssignableFrom<IStatusCodeHttpResult>(result);
        Assert.Equal(StatusCodes.Status409Conflict, status.StatusCode);
    }

    [Fact(DisplayName = "✓ Stripe-Style: Replays exact cached response instead of returning empty 204")]
    public async Task InvokeAsync_WhenDuplicateCompletedRequest_ReplaysCachedResponse()
    {
        var store = new Mock<IIdempotencyStore>();
        var cachedResponse = new CachedHttpResponse(201, "application/json", "{\"id\":\"doc-123\"}"u8.ToArray());

        store.Setup(x => x.TryAcquireAsync(
                It.IsAny<string>(),
                It.IsAny<TimeSpan>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync((IdempotencyAcquireResult.Completed, cachedResponse));

        var filter = CreateFilter(store);
        var context = CreateContext();
        context.HttpContext.Request.Headers["Idempotency-Key"] = "a8a67f6f-7f6f-4f71-b3a6-6bce6f04c6d2";

        context.HttpContext.Response.Body = new MemoryStream();

        var result = await filter.InvokeAsync(context,
            _ => throw new InvalidOperationException("should not execute"));

        var replayResult = Assert.IsType<IdempotencyReplayResult>(result);
        await replayResult.ExecuteAsync(context.HttpContext);

        Assert.Equal(StatusCodes.Status201Created, context.HttpContext.Response.StatusCode);
        Assert.Equal("application/json", context.HttpContext.Response.ContentType);
    }

    [Fact(DisplayName = "✓ Captures stream successfully and marks completed in the store")]
    public async Task InvokeAsync_WhenSuccessfulRequest_StoresIdempotencyKey()
    {
        var store = new Mock<IIdempotencyStore>();
        store.Setup(x => x.TryAcquireAsync(
                It.IsAny<string>(),
                It.IsAny<TimeSpan>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync((IdempotencyAcquireResult.Acquired, (CachedHttpResponse?)null));

        store.Setup(x => x.MarkCompletedAsync(
                It.IsAny<string>(),
                It.IsAny<CachedHttpResponse>(),
                It.IsAny<TimeSpan>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var filter = CreateFilter(store);
        var context = CreateContext();
        context.HttpContext.Request.Headers["Idempotency-Key"] = "13b33980-5b58-4974-b080-bb4ecff97327";

        var okResult = TypedResults.Ok(new { status = "ok" });

        var result = await filter.InvokeAsync(context,
            _ => ValueTask.FromResult<object?>(okResult));

        var saveResult = Assert.IsType<IdempotencySaveResult>(result);
        await saveResult.ExecuteAsync(context.HttpContext);

        store.Verify(x => x.MarkCompletedAsync(
                It.IsAny<string>(),
                It.IsAny<CachedHttpResponse>(),
                It.IsAny<TimeSpan>(),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    private static IdempotencyFilter CreateFilter(Mock<IIdempotencyStore> store)
        => new(store.Object, NullLogger<IdempotencyFilter>.Instance);

    private static TestEndpointFilterInvocationContext CreateContext()
    {
        var services = new ServiceCollection();

        services.AddLogging();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = services.BuildServiceProvider(),
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-1")], "test"))
        };

        return new TestEndpointFilterInvocationContext(httpContext);
    }

    private sealed class TestEndpointFilterInvocationContext(HttpContext httpContext) : EndpointFilterInvocationContext
    {
        private readonly object?[] _arguments = [];

        public override HttpContext HttpContext { get; } = httpContext;

        public override IList<object?> Arguments => _arguments;

        public override T GetArgument<T>(int index) => (T)_arguments[index]!;
    }
}
