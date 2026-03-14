using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Sentinel.Middleware.Filters;
using StackExchange.Redis;
using System.Security.Claims;

namespace Sentinel.Tests.Unit;

public sealed class RequireIdempotencyAttributeTests
{
    [Fact]
    public async Task OnActionExecutionAsync_WhenHeaderMissing_ReturnsBadRequest()
    {
        var attribute = new RequireIdempotencyAttribute();
        var context = CreateActionExecutingContext();

        await attribute.OnActionExecutionAsync(context, () => throw new InvalidOperationException("should not execute"));

        var result = Assert.IsType<BadRequestObjectResult>(context.Result);
        Assert.Equal(StatusCodes.Status400BadRequest, result.StatusCode);
    }

    [Fact]
    public async Task OnActionExecutionAsync_WhenDuplicateKey_ReturnsConflict()
    {
        var attribute = new RequireIdempotencyAttribute();
        var context = CreateActionExecutingContext(db =>
        {
            db.SetReturnsDefault(Task.FromResult(false));
        });
        context.HttpContext.Request.Headers["Idempotency-Key"] = "dup-1";

        await attribute.OnActionExecutionAsync(context, () => throw new InvalidOperationException("should not execute"));

        var result = Assert.IsType<ConflictObjectResult>(context.Result);
        Assert.Equal(StatusCodes.Status409Conflict, result.StatusCode);
    }

    [Fact]
    public async Task OnActionExecutionAsync_WhenSuccessfulRequest_StoresIdempotencyKey()
    {
        var attribute = new RequireIdempotencyAttribute();
        var context = CreateActionExecutingContext(db =>
        {
            db.SetReturnsDefault(Task.FromResult(true));
        });
        context.HttpContext.Request.Headers["Idempotency-Key"] = "ok-1";

        await attribute.OnActionExecutionAsync(context, NextOk(context));

        Assert.Null(context.Result);
    }

    private static ActionExecutionDelegate NextOk(ActionExecutingContext context)
    {
        return () =>
        {
            var executed = new ActionExecutedContext(context, context.Filters, context.Controller)
            {
                Result = new OkObjectResult(new { status = "ok" })
            };
            return Task.FromResult(executed);
        };
    }

    private static ActionExecutingContext CreateActionExecutingContext(Action<Mock<IDatabase>>? configureDb = null)
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

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor(), new ModelStateDictionary());
        return new ActionExecutingContext(actionContext, [], new Dictionary<string, object?>(), controller: new object());
    }
}
