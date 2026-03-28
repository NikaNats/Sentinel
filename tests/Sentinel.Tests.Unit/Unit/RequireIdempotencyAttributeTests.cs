using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Sentinel.AspNetCore.Filters;
using StackExchange.Redis;

namespace Sentinel.Tests.Unit;

public sealed class RequireIdempotencyAttributeTests
{
    [Fact]
    public async Task InvokeAsync_WhenHeaderMissing_ReturnsBadRequest()
    {
        var filter = new IdempotencyFilter();
        var context = CreateContext();

        var result = await filter.InvokeAsync(context,
            _ => throw new InvalidOperationException("should not execute"));

        var status = Assert.IsAssignableFrom<IStatusCodeHttpResult>(result);
        Assert.Equal(StatusCodes.Status400BadRequest, status.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenDuplicateKey_ReturnsConflict()
    {
        var filter = new IdempotencyFilter();
        var context = CreateContext(db =>
        {
            db.Setup(x => x.StringSetAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(),
                    When.NotExists, It.IsAny<CommandFlags>()))
                .ReturnsAsync(false);
            db.Setup(x => x.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
                .ReturnsAsync("IN_PROGRESS");
        });
        context.HttpContext.Request.Headers["Idempotency-Key"] = "6f836f95-7f22-4eb9-b854-8e8be2df40e8";

        var result = await filter.InvokeAsync(context,
            _ => throw new InvalidOperationException("should not execute"));

        var status = Assert.IsAssignableFrom<IStatusCodeHttpResult>(result);
        Assert.Equal(StatusCodes.Status409Conflict, status.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenDuplicateCompletedRequest_ReturnsNoContent()
    {
        var filter = new IdempotencyFilter();
        var context = CreateContext(db =>
        {
            db.Setup(x => x.StringSetAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(),
                    When.NotExists, It.IsAny<CommandFlags>()))
                .ReturnsAsync(false);
            db.Setup(x => x.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
                .ReturnsAsync("COMPLETED");
        });
        context.HttpContext.Request.Headers["Idempotency-Key"] = "a8a67f6f-7f6f-4f71-b3a6-6bce6f04c6d2";

        var result = await filter.InvokeAsync(context,
            _ => throw new InvalidOperationException("should not execute"));

        var status = Assert.IsAssignableFrom<IStatusCodeHttpResult>(result);
        Assert.Equal(StatusCodes.Status204NoContent, status.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenSuccessfulRequest_StoresIdempotencyKey()
    {
        var filter = new IdempotencyFilter();
        var context = CreateContext(db =>
        {
            db.SetupSequence(x => x.StringSetAsync(
                    It.IsAny<RedisKey>(),
                    It.IsAny<RedisValue>(),
                    It.IsAny<TimeSpan?>(),
                    It.IsAny<When>(),
                    It.IsAny<CommandFlags>()))
                .ReturnsAsync(true)
                .ReturnsAsync(true);
        });
        context.HttpContext.Request.Headers["Idempotency-Key"] = "13b33980-5b58-4974-b080-bb4ecff97327";

        var result = await filter.InvokeAsync(context,
            _ => ValueTask.FromResult<object?>(TypedResults.Ok(new { status = "ok" })));

        var status = Assert.IsAssignableFrom<IStatusCodeHttpResult>(result);
        Assert.Equal(StatusCodes.Status200OK, status.StatusCode);
    }

    private static TestEndpointFilterInvocationContext CreateContext(Action<Mock<IDatabase>>? configureDb = null)
    {
        var dbMock = new Mock<IDatabase>();
        configureDb?.Invoke(dbMock);

        var multiplexerMock = new Mock<IConnectionMultiplexer>();
        multiplexerMock
            .Setup(x => x.GetDatabase(It.IsAny<int>(), It.IsAny<object?>()))
            .Returns(dbMock.Object);

        var services = new ServiceCollection();
        services.AddSingleton(_ => multiplexerMock.Object);

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

        public override T GetArgument<T>(int index)
        {
            return (T)_arguments[index]!;
        }
    }
}
